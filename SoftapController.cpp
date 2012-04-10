/*
 * Copyright (C) 2008 The Android Open Source Project
 * Copyright (c) 2012 Eduardo José Tagle <ejtagle@tutopia.com> 
 *  -Added AR6002 hostAp support
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>

#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <dirent.h>
#include <poll.h> 

#include <netinet/in.h>
#include <arpa/inet.h>

#include <linux/wireless.h>

#include <openssl/evp.h>
#include <openssl/sha.h>

#define LOG_TAG "SoftapController"
#include <cutils/log.h>
#include <cutils/properties.h>
#include <netutils/ifc.h>
#include <private/android_filesystem_config.h>
#include "wifi.h"

#include "SoftapController.h"

static const char HOSTAPD_CONF_FILE[]    = "/data/misc/wifi/hostapd.conf";

#ifdef AR6002_WIFI

/* AR6002 support */
extern "C" int delete_module(const char *, unsigned int);
extern "C" int init_module(void * , unsigned int, const char *);
extern "C" void *load_file(const char *fn, unsigned *_sz);

static int insmod(const char *filename, const char *args)
{
    void *module;
    unsigned int size;
    int ret;

    module = load_file(filename, &size);
    if (!module)
        return -1;

    ret = init_module(module, size, args);

    free(module);

    return ret;
}

static int rmmod(const char *modname)
{
    int ret = -1;
    int maxtry = 10;

    while (maxtry-- > 0) {
        ret = delete_module(modname, O_NONBLOCK | O_EXCL);
        if (ret < 0 && errno == EAGAIN)
            usleep(500000);
        else
            break;
    }

    if (ret != 0)
        LOGD("Unable to unload driver module \"%s\": %s\n",
             modname, strerror(errno));
    return ret;
} 
 

#ifdef HAVE_LIBC_SYSTEM_PROPERTIES
#define _REALLY_INCLUDE_SYS__SYSTEM_PROPERTIES_H_
#include <sys/_system_properties.h>
#endif

#include <sys/system_properties.h>
#include "libwpa_client/wpa_ctrl.h"


static const char IFACE_DIR[]            = "/data/misc/wifi/hostapd";
static const char HOSTAPD_NAME[]     	 = "hostapd";
static const char HOSTAPD_CONF_TEMPLATE[]= "/system/etc/wifi/hostapd.conf";
static const char HOSTAPD_PROP_NAME[]    = "init.svc.hostapd";
static const char MODULE_FILE[]          = "/proc/modules";
static const char DRIVER_MODULE_NAME[]   = WIFI_DRIVER_MODULE_NAME;
static const char DRIVER_MODULE_TAG[]    = WIFI_DRIVER_MODULE_NAME " ";
static const char DRIVER_MODULE_PATH[]   = WIFI_DRIVER_MODULE_PATH;

/*#define AP_IFNAME_PREFIX "athap"*/
#define AP_IFNAME_PREFIX "wlan"

#define AR6002AP_IFNAME AP_IFNAME_PREFIX "0"

#ifndef WIFI_DRIVER_LOADER_DELAY
#define WIFI_DRIVER_LOADER_DELAY	1000000
#endif

#define WIFI_DEFAULT_BI         100         /* in TU */
#define WIFI_DEFAULT_DTIM       1           /* in beacon */
#define WIFI_DEFAULT_CHANNEL    6
#define WIFI_DEFAULT_MAX_STA    8
#define WIFI_DEFAULT_PREAMBLE   0

static struct wpa_ctrl *ctrl_conn = NULL;
static int mProfileValid = 0;

/* make sure the hostapd config exists */
static int ensure_config_file_exists()
{
    char buf[2048];
    int srcfd, destfd;
    int nread;

	/* If the file exists, we are done! */
    if (access(HOSTAPD_CONF_FILE, R_OK|W_OK) == 0) {
        return 0;
    } else if (errno != ENOENT) {
        LOGE("Cannot access \"%s\": %s", HOSTAPD_CONF_FILE, strerror(errno));
        return -1;
    }

	/* Otherwise, copy the template as a default starting point */
    srcfd = open(HOSTAPD_CONF_TEMPLATE, O_RDONLY);
    if (srcfd < 0) {
        LOGE("Cannot open \"%s\": %s", HOSTAPD_CONF_TEMPLATE, strerror(errno));
        return -1;
    }

    destfd = open(HOSTAPD_CONF_FILE, O_CREAT|O_WRONLY, 0660);
    if (destfd < 0) {
        close(srcfd);
        LOGE("Cannot create \"%s\": %s", HOSTAPD_CONF_FILE, strerror(errno));
        return -1;
    }

    while ((nread = read(srcfd, buf, sizeof(buf))) != 0) {
        if (nread < 0) {
            LOGE("Error reading \"%s\": %s", HOSTAPD_CONF_TEMPLATE, strerror(errno));
            close(srcfd);
            close(destfd);
            unlink(HOSTAPD_CONF_FILE);
            return -1;
        }
        write(destfd, buf, nread);
    }

    close(destfd);
    close(srcfd);
	
    /* chmod is needed because open() didn't set permisions properly */
    if (chmod(HOSTAPD_CONF_FILE, 0660) < 0) {
        LOGE("Error changing permissions of %s to 0660: %s",
             HOSTAPD_CONF_FILE, strerror(errno));
        unlink(HOSTAPD_CONF_FILE);
        return -1;
    }

    if (chown(HOSTAPD_CONF_FILE, AID_SYSTEM, AID_WIFI) < 0) {
        LOGE("Error changing group ownership of %s to %d: %s",
             HOSTAPD_CONF_FILE, AID_WIFI, strerror(errno));
        unlink(HOSTAPD_CONF_FILE);
        return -1;
    }

    return 0;
}

/**
 * wifi_hostap_ctrl_cleanup() - Delete any local UNIX domain socket files that
 * may be left over from clients that were previously connected to
 * wpa_supplicant. This keeps these files from being orphaned in the
 * event of crashes that prevented them from being removed as part
 * of the normal orderly shutdown.
 */
static void wifi_hostap_ctrl_cleanup(void)
{
    DIR *dir;
    struct dirent entry;
    struct dirent *result;
    size_t dirnamelen;
    size_t maxcopy;
    char pathname[PATH_MAX];
    char *namep;
    const char *local_socket_dir = IFACE_DIR;
    const char *local_socket_prefix = AP_IFNAME_PREFIX;

    if ((dir = opendir(local_socket_dir)) == NULL)
        return;

    dirnamelen = (size_t)snprintf(pathname, sizeof(pathname), "%s/", local_socket_dir);
    if (dirnamelen >= sizeof(pathname)) {
        closedir(dir);
        return;
    }
    namep = pathname + dirnamelen;
    maxcopy = PATH_MAX - dirnamelen;
    while (readdir_r(dir, &entry, &result) == 0 && result != NULL) {
        if (strncmp(entry.d_name, local_socket_prefix, strlen(local_socket_prefix)) == 0) {
            if (strlcpy(namep, entry.d_name, maxcopy) < maxcopy) {
                unlink(pathname);
            }
        }
    }
    closedir(dir);
}

/* check if wifi driver is loaded */
static int is_wifi_module_loaded() 
{
    FILE *proc;
    char line[sizeof(DRIVER_MODULE_TAG)+10];
    /*
     * If the property says the driver is loaded, check to
     * make sure that the property setting isn't just left
     * over from a previous manual shutdown or a runtime
     * crash.
     */
    if ((proc = fopen(MODULE_FILE, "r")) == NULL) {
        LOGW("Could not open %s: %s", MODULE_FILE, strerror(errno));
        return 0;
    }
    while ((fgets(line, sizeof(line), proc)) != NULL) {
        if (strncmp(line, DRIVER_MODULE_TAG, sizeof(DRIVER_MODULE_TAG)) == 0) {
            fclose(proc);
            return 1;
        }
    }
    fclose(proc);
    return 0;
}

/* unload wifi driver */
static int wifi_unload_module()
{
    usleep(200000); /* allow to finish interface down */
	
    if (rmmod(DRIVER_MODULE_NAME) == 0) {
        int count = 20; /* wait at most 10 seconds for completion */
        while (count-- > 0) {
            if (!is_wifi_module_loaded())
                break;
            usleep(500000);
        }
        usleep(500000); /* allow card removal */
        if (count) {
            return 0;
        }
        return -1;
    } else
        return -1;
} 
 

/* start the hostapd daemon */
static int wifi_start_hostapd()
{
    char supp_status[PROPERTY_VALUE_MAX] = {'\0'};
    int count = 300; /* wait at most 30 seconds for completion */
    char mac_buff[15] = {'\0'};
#ifdef HAVE_LIBC_SYSTEM_PROPERTIES
    const prop_info *pi;
    unsigned serial = 0;
#endif

    /* Check whether already running */
    if (property_get(HOSTAPD_PROP_NAME, supp_status, NULL)
            && strcmp(supp_status, "running") == 0) {
        return 0;
    }
	
    /* Before starting the daemon, make sure its config file exists */
    if (ensure_config_file_exists() < 0) {
        LOGE("Wi-Fi HostAP will not be enabled");
        return -1;
    }

    /* Clear out any stale socket files that might be left over. */
    wifi_hostap_ctrl_cleanup();

#ifdef HAVE_LIBC_SYSTEM_PROPERTIES
    /*
     * Get a reference to the status property, so we can distinguish
     * the case where it goes stopped => running => stopped (i.e.,
     * it start up, but fails right away) from the case in which
     * it starts in the stopped state and never manages to start
     * running at all.
     */
    pi = __system_property_find(HOSTAPD_PROP_NAME);
    if (pi != NULL) {
        serial = pi->serial;
    }
#endif
    property_set("ctl.start", HOSTAPD_NAME);
    sched_yield();

    while (count-- > 0) {
#ifdef HAVE_LIBC_SYSTEM_PROPERTIES
        if (pi == NULL) {
            pi = __system_property_find(HOSTAPD_PROP_NAME);
        }
        if (pi != NULL) {
            __system_property_read(pi, NULL, supp_status);
            if (strcmp(supp_status, "running") == 0) {
                return 0;
            } else if (pi->serial != serial &&
                    strcmp(supp_status, "stopped") == 0) {
                return -1;
            }
        }
#else
        if (property_get(HOSTAPD_PROP_NAME, supp_status, NULL)) {
            if (strcmp(supp_status, "running") == 0)
                return 0;
        }
#endif

        usleep(100000);
    }
    return -1;
}

/* stop the hostapd daemon */
static int wifi_stop_hostapd()
{
    char supp_status[PROPERTY_VALUE_MAX] = {'\0'};
    int count = 50; /* wait at most 5 seconds for completion */

    /* Check whether hostapd already stopped */
    if (property_get(HOSTAPD_PROP_NAME, supp_status, NULL)
        && strcmp(supp_status, "stopped") == 0) {
        return 0;
    }

    property_set("ctl.stop", HOSTAPD_NAME);
    sched_yield();

    while (count-- > 0) {
        if (property_get(HOSTAPD_PROP_NAME, supp_status, NULL)) {
            if (strcmp(supp_status, "stopped") == 0)
                return 0;
        }
        usleep(100000);
    }
    return -1;
}

/* Connect to hostapd */
static int wifi_connect_to_hostapd()
{
    char ifname[256];
    char supp_status[PROPERTY_VALUE_MAX] = {'\0'};

    /* Make sure hostapd is running */
    if (!property_get(HOSTAPD_PROP_NAME, supp_status, NULL)
            || strcmp(supp_status, "running") != 0) {
        LOGE("hostapd not running, cannot connect");
        return -1;
    }

    if (access(IFACE_DIR, F_OK) == 0) {
        snprintf(ifname, sizeof(ifname), "%s/%s", IFACE_DIR, AR6002AP_IFNAME);
    } else {
        strlcpy(ifname, AR6002AP_IFNAME, sizeof(ifname));
    }
    LOGD("ifname = %s\n", ifname);

    { /* check iface file is ready */
	    int cnt = 160; /* 8 seconds (160*50)*/
	    sched_yield();
		
		while (cnt--) {
			if (access(ifname, F_OK|W_OK)==0) {
				LOGD("ifname %s is ready to read/write cnt=%d\n", ifname, cnt);

				/* Attach to monitor hostapd activity */
				ctrl_conn = wpa_ctrl_open(ifname);
				
				/* if done, break */
				if (ctrl_conn)
					break;
			}
			usleep(50000);
		}
    }

    if (ctrl_conn == NULL) {
        LOGE("Unable to open connection to hostapd on \"%s\": %s",
             ifname, strerror(errno));
        return -1;
    }
    if (wpa_ctrl_attach(ctrl_conn) != 0) {
        wpa_ctrl_close(ctrl_conn);
        ctrl_conn = NULL;
        return -1;
    }
    return 0;
}

/* Called to dump hostapd messages */
static void hostapd_cli_msg_cb(char *msg, size_t len)
{
	LOGD("%s\n", msg);
}

static int wpa_ctrl_command_sta(const char *cmd, char *addr, size_t addr_len)
{
	char buf[4096], *pos;
	size_t len;
	int ret;

	if (ctrl_conn == NULL) {
		LOGE("Not connected to hostapd - command dropped.\n");
		return -1;
	}
	len = sizeof(buf) - 1;
	ret = wpa_ctrl_request(ctrl_conn, cmd, strlen(cmd), buf, &len,
			       hostapd_cli_msg_cb);
	if (ret == -2) {
		LOGE("'%s' command timed out.\n", cmd);
		return -2;
	} else if (ret < 0) {
		LOGE("'%s' command failed.\n", cmd);
		return -1;
	}

	buf[len] = '\0';
	if (memcmp(buf, "FAIL", 4) == 0)
		return -1;

	LOGD("%s", buf);

	pos = buf;
	while (*pos != '\0' && *pos != '\n')
		pos++;
	*pos = '\0';
	strlcpy(addr, buf, addr_len);
	return 0;
} 


static void wifi_close_hostapd_connection()
{
    if (ctrl_conn != NULL) {
        wpa_ctrl_close(ctrl_conn);
        ctrl_conn = NULL;
    }
}

static int wifi_load_profile(bool started)
{
    if ((started) && (mProfileValid)) {
        if (ctrl_conn == NULL) {
            return -1;
        }
    }
    return 0;
}

#endif

SoftapController::SoftapController() {
    mPid = 0;
    mSock = socket(AF_INET, SOCK_DGRAM, 0);
    if (mSock < 0)
        LOGE("Failed to open socket");
    memset(mIface, 0, sizeof(mIface));

#ifdef AR6002_WIFI	
    mProfileValid = 0;
    ctrl_conn = NULL;
#endif

}

SoftapController::~SoftapController() {
    if (mSock >= 0)
        close(mSock);
}

int SoftapController::setCommand(char *iface, const char *fname, unsigned buflen) {
#ifdef HAVE_HOSTAPD
    return 0;
#else
    char tBuf[SOFTAP_MAX_BUFFER_SIZE];
    struct iwreq wrq;
    struct iw_priv_args *priv_ptr;
    int i, j, ret;
    int cmd = 0, sub_cmd = 0;

    strncpy(wrq.ifr_name, iface, sizeof(wrq.ifr_name));
    wrq.u.data.pointer = tBuf;
    wrq.u.data.length = sizeof(tBuf) / sizeof(struct iw_priv_args);
    wrq.u.data.flags = 0;
    if ((ret = ioctl(mSock, SIOCGIWPRIV, &wrq)) < 0) {
        LOGE("SIOCGIPRIV failed: %d", ret);
        return ret;
    }

    priv_ptr = (struct iw_priv_args *)wrq.u.data.pointer;
    for(i=0; i < wrq.u.data.length;i++) {
        if (strcmp(priv_ptr[i].name, fname) == 0) {
            cmd = priv_ptr[i].cmd;
            break;
        }
    }

    if (i == wrq.u.data.length) {
        LOGE("iface:%s, fname: %s - function not supported", iface, fname);
        return -1;
    }

    if (cmd < SIOCDEVPRIVATE) {
        for(j=0; j < i; j++) {
            if ((priv_ptr[j].set_args == priv_ptr[i].set_args) &&
                (priv_ptr[j].get_args == priv_ptr[i].get_args) &&
                (priv_ptr[j].name[0] == '\0'))
                break;
        }
        if (j == i) {
            LOGE("iface:%s, fname: %s - invalid private ioctl", iface, fname);
            return -1;
        }
        sub_cmd = cmd;
        cmd = priv_ptr[j].cmd;
    }

    strncpy(wrq.ifr_name, iface, sizeof(wrq.ifr_name));
    if ((buflen == 0) && (*mBuf != 0))
        wrq.u.data.length = strlen(mBuf) + 1;
    else
        wrq.u.data.length = buflen;
    wrq.u.data.pointer = mBuf;
    wrq.u.data.flags = sub_cmd;
    ret = ioctl(mSock, cmd, &wrq);
    return ret;
#endif
}

int SoftapController::startDriver(char *iface) {
    int ret;

    if (mSock < 0) {
        LOGE("Softap driver start - failed to open socket");
        return -1;
    }
    if (!iface || (iface[0] == '\0')) {
        LOGD("Softap driver start - wrong interface");
        iface = mIface;
    }

#ifndef AR6002_WIFI
	/* Original way */
    *mBuf = 0;
    ret = setCommand(iface, "START");
    if (ret < 0) {
        LOGE("Softap driver start: %d", ret);
        return ret;
    }
	
#ifdef HAVE_HOSTAPD
    ifc_init();
    ret = ifc_up(iface);
    ifc_close();
#endif

#else

	/* Just bring up the interface */
    ifc_init();
    ret = ifc_up(AR6002AP_IFNAME);
    ifc_close();

#endif

    usleep(AP_DRIVER_START_DELAY);
	
    LOGD("Softap driver start: %d", ret);
    return ret;
}

int SoftapController::stopDriver(char *iface) {
    int ret;

    if (mSock < 0) {
        LOGE("Softap driver stop - failed to open socket");
        return -1;
    }
    if (!iface || (iface[0] == '\0')) {
        LOGD("Softap driver stop - wrong interface");
        iface = mIface;
    }
    *mBuf = 0;
	
#ifndef AR6002_WIFI

	/* Original way */
#ifdef HAVE_HOSTAPD
    ifc_init();
    ret = ifc_down(iface);
    ifc_close();
    if (ret < 0) {
        LOGE("Softap %s down: %d", iface, ret);
    }
#endif

    ret = setCommand(iface, "STOP");

#else

	/* Just bring down the interface */
    ifc_init();
    ret = ifc_down(AR6002AP_IFNAME);
    ifc_close();
    if (ret < 0) {
        LOGE("Softap %s down: %d", AR6002AP_IFNAME, ret);
    }

#endif

    LOGD("Softap driver stop: %d", ret);
    return ret;
}

int SoftapController::startSoftap() {
    pid_t pid = 1;
    int ret = 0;

    if (mPid) {
        LOGE("Softap already started");
        return 0;
    }
    if (mSock < 0) {
        LOGE("Softap startap - failed to open socket");
        return -1;
    }
	
#ifndef AR6002_WIFI

	/* original way */
#ifdef HAVE_HOSTAPD
    if ((pid = fork()) < 0) {
        LOGE("fork failed (%s)", strerror(errno));
        return -1;
    }
#endif
    if (!pid) {
#ifdef HAVE_HOSTAPD

        ensure_entropy_file_exists();
        if (execl("/system/bin/hostapd", "/system/bin/hostapd",
                  "-e", WIFI_ENTROPY_FILE,
                  HOSTAPD_CONF_FILE, (char *) NULL)) {
            LOGE("execl failed (%s)", strerror(errno));
        }
#endif
        LOGE("Should never get here!");
        return -1;
    } else {
        *mBuf = 0;
        ret = setCommand(mIface, "AP_BSS_START");
        if (ret) {
            LOGE("Softap startap - failed: %d", ret);
        }
        else {
           mPid = pid;
           LOGD("Softap startap - Ok");
           usleep(AP_BSS_START_DELAY);
        }
    }
	
#else

	/* AR6002 specific */
	
	/* Before starting the daemon, make sure its config file exists */
	ret = ensure_config_file_exists();
	if (ret < 0) {
		LOGE("Softap startup - configuration file missing");
		stopDriver((char*)AR6002AP_IFNAME);
		return -1;
	}
	
	ret = wifi_start_hostapd();
	if (ret < 0) {
		LOGE("Softap startap - starting hostapd fails");
		stopDriver((char*)AR6002AP_IFNAME);
		return -1;
	}

	sched_yield();
	usleep(100000);

	ret = wifi_connect_to_hostapd();
	if (ret < 0) {
		LOGE("Softap startap - connect to hostapd fails");
		return -1;
	}

	/* Indicate interface up */
	ret = wifi_load_profile(true);
	if (ret < 0) {
		LOGE("Softap startap - load new configuration fails");
		return -1;
	}
	if (ret) {
		LOGE("Softap startap - failed: %d", ret);
	}
	else {
	   mPid = pid;
	   LOGD("Softap startap - Ok");
	   usleep(AP_BSS_START_DELAY);
	}
	
#endif

    return ret;

}

int SoftapController::stopSoftap() {
    int ret;

    if (mPid == 0) {
        LOGE("Softap already stopped");
        return 0;
    }

#ifndef AR6002_WIFI		

	/* Original way */
#ifdef HAVE_HOSTAPD
    LOGD("Stopping Softap service");
    kill(mPid, SIGTERM);
    waitpid(mPid, NULL, 0);
#endif
    if (mSock < 0) {
        LOGE("Softap stopap - failed to open socket");
        return -1;
    }
	
    *mBuf = 0;
    ret = setCommand(mIface, "AP_BSS_STOP");
	
#else

	/* Stop hostapd service */
	ret = wifi_stop_hostapd();
	
#endif

    mPid = 0;
    LOGD("Softap service stopped: %d", ret);
    usleep(AP_BSS_STOP_DELAY);
    return ret;
}

bool SoftapController::isSoftapStarted() {
    return (mPid != 0 ? true : false);
}

int SoftapController::addParam(int pos, const char *cmd, const char *arg)
{
    if (pos < 0)
        return pos;
    if ((unsigned)(pos + strlen(cmd) + strlen(arg) + 1) >= sizeof(mBuf)) {
        LOGE("Command line is too big");
        return -1;
    }
    pos += sprintf(&mBuf[pos], "%s=%s,", cmd, arg);
    return pos;
}

/*
 * Arguments:
 *      argv[2] - wlan interface
 *      argv[3] - softap interface
 *      argv[4] - SSID
 *	argv[5] - Security
 *	argv[6] - Key
 *	argv[7] - Channel
 *	argv[8] - Preamble
 *	argv[9] - Max SCB
 */
int SoftapController::setSoftap(int argc, char *argv[]) {
    char psk_str[2*SHA256_DIGEST_LENGTH+1];
    int ret = 0, i = 0, fd;
    char *ssid, *iface;

    if (mSock < 0) {
        LOGE("Softap set - failed to open socket");
        return -1;
    }
    if (argc < 4) {
        LOGE("Softap set - missing arguments");
        return -1;
    }

    strncpy(mIface, argv[3], sizeof(mIface));
    iface = argv[2];

#ifndef AR6002_WIFI	

	/* Original way */
#ifdef HAVE_HOSTAPD
    char *wbuf = NULL;
    char *fbuf = NULL;

    if (argc > 4) {
        ssid = argv[4];
    } else {
        ssid = (char *)"AndroidAP";
    }

    asprintf(&wbuf, "interface=%s\ndriver=nl80211\nctrl_interface="
            "/data/misc/wifi/hostapd\nssid=%s\nchannel=6\n", iface, ssid);

    if (argc > 5) {
        if (!strcmp(argv[5], "wpa-psk")) {
            generatePsk(ssid, argv[6], psk_str);
            asprintf(&fbuf, "%swpa=1\nwpa_pairwise=TKIP CCMP\nwpa_psk=%s\n", wbuf, psk_str);
        } else if (!strcmp(argv[5], "wpa2-psk")) {
            generatePsk(ssid, argv[6], psk_str);
            asprintf(&fbuf, "%swpa=2\nrsn_pairwise=CCMP\nwpa_psk=%s\n", wbuf, psk_str);
        } else if (!strcmp(argv[5], "open")) {
            asprintf(&fbuf, "%s", wbuf);
        }
    } else {
        asprintf(&fbuf, "%s", wbuf);
    }

    fd = open(HOSTAPD_CONF_FILE, O_CREAT | O_TRUNC | O_WRONLY, 0660);
    if (fd < 0) {
        LOGE("Cannot update \"%s\": %s", HOSTAPD_CONF_FILE, strerror(errno));
        free(wbuf);
        free(fbuf);
        return -1;
    }
    if (write(fd, fbuf, strlen(fbuf)) < 0) {
        LOGE("Cannot write to \"%s\": %s", HOSTAPD_CONF_FILE, strerror(errno));
        ret = -1;
    }
    close(fd);
    free(wbuf);
    free(fbuf);

    /* Note: apparently open can fail to set permissions correctly at times */
    if (chmod(HOSTAPD_CONF_FILE, 0660) < 0) {
        LOGE("Error changing permissions of %s to 0660: %s",
                HOSTAPD_CONF_FILE, strerror(errno));
        unlink(HOSTAPD_CONF_FILE);
        return -1;
    }

    if (chown(HOSTAPD_CONF_FILE, AID_SYSTEM, AID_WIFI) < 0) {
        LOGE("Error changing group ownership of %s to %d: %s",
                HOSTAPD_CONF_FILE, AID_WIFI, strerror(errno));
        unlink(HOSTAPD_CONF_FILE);
        return -1;
    }

#else

    /* Create command line */
    i = addParam(i, "ASCII_CMD", "AP_CFG");
    if (argc > 4) {
        ssid = argv[4];
    } else {
        ssid = (char *)"AndroidAP";
    }
    i = addParam(i, "SSID", ssid);
    if (argc > 5) {
        i = addParam(i, "SEC", argv[5]);
    } else {
        i = addParam(i, "SEC", "open");
    }
    if (argc > 6) {
        generatePsk(ssid, argv[6], psk_str);
        i = addParam(i, "KEY", psk_str);
    } else {
        i = addParam(i, "KEY", "12345678");
    }
    if (argc > 7) {
        i = addParam(i, "CHANNEL", argv[7]);
    } else {
        i = addParam(i, "CHANNEL", "6");
    }
    if (argc > 8) {
        i = addParam(i, "PREAMBLE", argv[8]);
    } else {
        i = addParam(i, "PREAMBLE", "0");
    }
    if (argc > 9) {
        i = addParam(i, "MAX_SCB", argv[9]);
    } else {
        i = addParam(i, "MAX_SCB", "8");
    }
    if ((i < 0) || ((unsigned)(i + 4) >= sizeof(mBuf))) {
        LOGE("Softap set - command is too big");
        return i;
    }
    sprintf(&mBuf[i], "END");

    /* system("iwpriv eth0 WL_AP_CFG ASCII_CMD=AP_CFG,SSID=\"AndroidAP\",SEC=\"open\",KEY=12345,CHANNEL=1,PREAMBLE=0,MAX_SCB=8,END"); */
    ret = setCommand(iface, "AP_SET_CFG");
    if (ret) {
        LOGE("Softap set - failed: %d", ret);
    }
    else {
        LOGD("Softap set - Ok");
        usleep(AP_SET_CFG_DELAY);
    }
#endif

#else

	/* AR6002 specific way */
    char *fbuf = NULL;

    if (argc > 4) {
        ssid = argv[4];
    } else {
        ssid = (char *)"AndroidAP";
    }

    fd = open(HOSTAPD_CONF_FILE, O_CREAT|O_WRONLY|O_TRUNC, 0660);
    if (fd < 0) {
        LOGE("Cannot create \"%s\": %s", HOSTAPD_CONF_FILE, strerror(errno));
        return -1;
    }

    asprintf(&fbuf, "interface=" AR6002AP_IFNAME "\n");
	if (write(fd, fbuf, strlen(fbuf)) < 0) goto wrerr;
	free(fbuf);
	
    asprintf(&fbuf, "ctrl_interface=%s\n" ,IFACE_DIR);
	if (write(fd, fbuf, strlen(fbuf)) < 0) goto wrerr;
	free(fbuf);
	
    asprintf(&fbuf, "ssid=%s\n" ,ssid);
	if (write(fd, fbuf, strlen(fbuf)) < 0) goto wrerr;
	free(fbuf);
	
    /* set open auth */
    asprintf(&fbuf, "auth_algs=1\n");
	if (write(fd, fbuf, strlen(fbuf)) < 0) goto wrerr;
	free(fbuf);
	
    asprintf(&fbuf, "max_num_sta=%d\n",WIFI_DEFAULT_MAX_STA);
	if (write(fd, fbuf, strlen(fbuf)) < 0) goto wrerr;
	free(fbuf);
	
    asprintf(&fbuf, "beacon_int=%d\n" ,WIFI_DEFAULT_BI);
	if (write(fd, fbuf, strlen(fbuf)) < 0) goto wrerr;
	free(fbuf);
	
    asprintf(&fbuf, "dtim_period=%d\n",WIFI_DEFAULT_DTIM);
	if (write(fd, fbuf, strlen(fbuf)) < 0) goto wrerr;
	free(fbuf);
	
    if (argc > 5) {
        if (!strcmp(argv[5], "wpa-psk")) {
            generatePsk(ssid, argv[6], psk_str);
			
            asprintf(&fbuf, "wpa=1\n");
			if (write(fd, fbuf, strlen(fbuf)) < 0) goto wrerr;
			free(fbuf);
			
			asprintf(&fbuf, "wpa_key_mgmt=WPA-PSK\n");
			if (write(fd, fbuf, strlen(fbuf)) < 0) goto wrerr;
			free(fbuf);

			asprintf(&fbuf, "wpa_pairwise=TKIP\n");
			if (write(fd, fbuf, strlen(fbuf)) < 0) goto wrerr;
			free(fbuf);
			
			asprintf(&fbuf, "wpa_psk=%s\n", psk_str);
			if (write(fd, fbuf, strlen(fbuf)) < 0) goto wrerr;
			free(fbuf);
			
		} else if (!strcmp(argv[5], "wpa2-psk")) {
		    generatePsk(ssid, argv[6], psk_str);
			
            asprintf(&fbuf, "wpa=2\n");
			if (write(fd, fbuf, strlen(fbuf)) < 0) goto wrerr;
			free(fbuf);

			asprintf(&fbuf, "wpa_key_mgmt=WPA-PSK\n");
			if (write(fd, fbuf, strlen(fbuf)) < 0) goto wrerr;
			free(fbuf);
			
            asprintf(&fbuf, "wpa_pairwise=CCMP\n");
			if (write(fd, fbuf, strlen(fbuf)) < 0) goto wrerr;
			free(fbuf);
			
			asprintf(&fbuf, "wpa_psk=%s\n", psk_str);
			if (write(fd, fbuf, strlen(fbuf)) < 0) goto wrerr;
			free(fbuf);
        }

		/* wpa-tkip
		wpa=1
		wpa_key_mgmt=WPA-PSK
		wpa_pairwise=TKIP
		wpa_passphrase=1234567890 
		*/
		/* WPA PSK
		wpa=2
		wpa_key_mgmt=WPA-PSK
		wpa_pairwise=CCMP
		wpa_passphrase=1234567890 
		*/
		/* WPA all
		wpa=3
		wpa_key_mgmt=WPA-PSK
		wpa_pairwise=TKIP CCMP
		wpa_passphrase=1234567890 
		*/
		/* wep open
		auth_algs=1
		wep_key0=1234567890
		wep_key1=0987654321
		wep_key2=1111111111
		wep_key3=2222222222
		wep_default_key=0 
		*/
		/* wep shared
		auth_algs=2
		wep_key0=1234567890
		wep_key1=0987654321
		wep_key2=1111111111
		wep_key3=2222222222
		wep_default_key=0 
		*/
    }
	
    if (argc > 7) {
        asprintf(&fbuf, "channel=%s\n",argv[7]);
    } else {
        asprintf(&fbuf, "channel=%d\n",WIFI_DEFAULT_CHANNEL);
    }
    if (write(fd, fbuf, strlen(fbuf)) < 0) {
wrerr:
        LOGE("Cannot write to \"%s\": %s", HOSTAPD_CONF_FILE, strerror(errno));
        ret = -1;
    }
	free(fbuf);
	
    /*if (argc > 8) {
        asprintf(&fbuf, sizeof(buf), "preamble=%s\n",argv[8]);
    } else {
        asprintf(&fbuf, sizeof(buf), "preamble=%d\n",WIFI_DEFAULT_PREAMBLE);
    }
	write(fd, fbuf, strlen(fbuf));	
	free(fbuf);
	*/

    close(fd);	

    /* Note: apparently open can fail to set permissions correctly at times */
    if (chmod(HOSTAPD_CONF_FILE, 0660) < 0) {
        LOGE("Error changing permissions of %s to 0660: %s",
                HOSTAPD_CONF_FILE, strerror(errno));
        unlink(HOSTAPD_CONF_FILE);
        return -1;
    }

    if (chown(HOSTAPD_CONF_FILE, AID_SYSTEM, AID_WIFI) < 0) {
        LOGE("Error changing group ownership of %s to %d: %s",
                HOSTAPD_CONF_FILE, AID_WIFI, strerror(errno));
        unlink(HOSTAPD_CONF_FILE);
        return -1;
    }
	
    mProfileValid = 1;

    ret = wifi_load_profile(isSoftapStarted());
    if (ret < 0) {
        LOGE("Softap set - load new configuration fails");
        return -1;
    }
    if (ret) {
        LOGE("Softap set - failed: %d", ret);
    }
    else {
        LOGD("Softap set - Ok");
        usleep(AP_SET_CFG_DELAY);
    }

#endif

    return ret;
}

void SoftapController::generatePsk(char *ssid, char *passphrase, char *psk_str) {
    unsigned char psk[SHA256_DIGEST_LENGTH];
    int j;
    // Use the PKCS#5 PBKDF2 with 4096 iterations
    PKCS5_PBKDF2_HMAC_SHA1(passphrase, strlen(passphrase),
            reinterpret_cast<const unsigned char *>(ssid), strlen(ssid),
            4096, SHA256_DIGEST_LENGTH, psk);
    for (j=0; j < SHA256_DIGEST_LENGTH; j++) {
        sprintf(&psk_str[j<<1], "%02x", psk[j]);
    }
    psk_str[j<<1] = '\0';
}


/*
 * Arguments:
 *	argv[2] - interface name
 *	argv[3] - AP or STA
 */
int SoftapController::fwReloadSoftap(int argc, char *argv[])
{
    int ret, i = 0;
    char *iface;
    char *fwpath;

    if (mSock < 0) {
        LOGE("Softap fwreload - failed to open socket");
        return -1;
    }
    if (argc < 4) {
        LOGE("Softap fwreload - missing arguments");
        return -1;
    }

    iface = argv[2];

#ifndef AR6002_WIFI

	/* original way */
    if (strcmp(argv[3], "AP") == 0) {
        fwpath = (char *)wifi_get_fw_path(WIFI_GET_FW_PATH_AP);
    } else if (strcmp(argv[3], "P2P") == 0) {
        fwpath = (char *)wifi_get_fw_path(WIFI_GET_FW_PATH_P2P);
    } else {
        fwpath = (char *)wifi_get_fw_path(WIFI_GET_FW_PATH_STA);
    }
    if (!fwpath)
        return -1;
#ifdef HAVE_HOSTAPD
    ret = wifi_change_fw_path((const char *)fwpath);
#else
    sprintf(mBuf, "FW_PATH=%s", fwpath);
    ret = setCommand(iface, "WL_FW_RELOAD");
#endif
	
#else

	/* AR6002 always uses the same fw -- But it must be reloaded with different params */ 
	ret = wifi_unload_module();
	if (ret) {
		LOGE("Softap fwReload - Firmware not loaded!");
	}
	
	/* If we are going to the hostAp or P2P mode ... */
    if (strcmp(argv[3], "AP") == 0 || strcmp(argv[3], "P2P") == 0) {
	
		/* AR6002 specific way. Load the module in hostap mode */
		ret = insmod(WIFI_DRIVER_MODULE_PATH, "fwmode=2 ifname=" AR6002AP_IFNAME);

    } else {
	
		/* AR6002 specific way. Load the module in sta mode */
		ret = insmod(WIFI_DRIVER_MODULE_PATH, "");

	}

	/* If we were able to reload the fw  ...*/
	if (!ret) {
		/* Give some time to initialize */
		usleep(WIFI_DRIVER_LOADER_DELAY);
	}
	
#endif

    if (ret) {
        LOGE("Softap fwReload - failed: %d", ret);
    }
    else {
        LOGD("Softap fwReload - Ok");
    }


    return ret;
}

int SoftapController::clientsSoftap(char **retbuf)
{
    int ret;

    if (mSock < 0) {
        LOGE("Softap clients - failed to open socket");
        return -1;
    }

#ifndef AR6002_WIFI	
	
	/* Original way */
    *mBuf = 0;
    ret = setCommand(mIface, "AP_GET_STA_LIST", SOFTAP_MAX_BUFFER_SIZE);
    if (ret) {
        LOGE("Softap clients - failed: %d", ret);
    } else {
        asprintf(retbuf, "Softap clients:%s", mBuf);
        LOGD("Softap clients:%s", mBuf);
    }
	
#else

	/* AR6002 way, using hostapd */
	char addr[32], cmd[64];
	
	if (wpa_ctrl_command_sta("STA-FIRST", addr, sizeof(addr)))
		return 0;
		
	asprintf(retbuf, "Softap clients:\n");
	do {
		char* buf;
		snprintf(cmd, sizeof(cmd), "STA-NEXT %s", addr);
		asprintf(&buf, "%s%s\n",*retbuf,addr);
		free(*retbuf);
		*retbuf = buf;
	} while (wpa_ctrl_command_sta( cmd, addr, sizeof(addr)) == 0);
	ret = 0;
	
#endif
    return ret;
}
