/* Copyright 2010 Markus Gutschke, markus at gutschke com
 *
 * This file can be distributed under the terms and conditions of the
 * GNU General Public License version 2 (or later).
 *
 * When running servers unattended, it is not uncommon for network problems
 * to occur due to faulty networking equipment. Quite frequently, power cycling
 * the networking equipment will restore network connectivity. This program
 * monitors the ability to access the internet, and once connectivity has been
 * lost, it will attempt to power cycle the networking equipment.
 *
 * It does this either by removing power from USB ports (if supported by the
 * USB hub) and restoring it after a couple of seconds; or alternatively,
 * it can talk a basic serial protocol to turn a relay on and off.
 *
 * Note: As most motherboard USB chips do not support power control, you will
 * probably have to use an external USB hub, or find a relay card that can
 * be addressed as a serial device (either RS232 or USB).
 *
 * The program will send out automatic notification emails whenever it took
 * an action or detected a problem.
 */
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <syslog.h>
#include <time.h>
#include <termios.h>
#include <unistd.h>
#include <usb.h>

// If defined, send e-mail to this user whenever we log any messages.
#ifndef emailUser
// #define emailUser "user@domain.test"
#endif

// If defined, connect to this server for outgoing e-mail.
#ifndef mailServer
// #define mailServer "mailserver.test"
#endif

// If defined, use serial port to control relay
#ifndef serialPort
// #define serialPort "/dev/ttyUSB0"
#endif

// Collect log messages for this much time until we send them by e-mail
static const int flushMessageTimeout   = 2*60;

// Number of seconds that we wait for a hostname to resolve and for that
// host to reply to a HEAD request.
static const int longHostTimeOut       = 20;
static const int shortHostTimeOut      = 5;

// Number of seconds that we sleep between probing the network.
static const int probeSleep            = 45;

// If a host is down, we exponentially decrease the rate of probing it. But
// after several cycles through the list of hosts, we see if it has come
// back.
static const int maxDisabledIterations = 16;

// Number of seconds that the power gets turned off when trying to reset
// the router.
static const int powercycleTime        = 45;

// If power cycling the router didn't fix the problem, wait at least this
// long before trying another powercyle.
static const int minPowercycleDelay    = 10*60;

// We exponentially increase the time between power cycles. Never increase
// the delay past this number.
static const int maxPowercycleDelay    = 8*60*60;

// List of well-known hosts that we probe in order to see if we have
// network connectivity.
// We want this list to include hostnames for entities that we expect to
// exist for a long time. We also want this list to be reasonably large, so
// that a) we can deal with hostnames becoming unavailable over time, and
// so that b) we don't connect to any one host too often.
// While the load that we cause to these hosts is minimal, we still try to
// pick really big sites, only. We want to be good citizens and minimize the
// impact that we have on other sites.
static const char *testHosts[] = {
  "about.com",
  "adobe.com",
  "akamai.com",
  "alibaba.com",
  "amazon.com",
  "aol.com",
  "ap.org",
  "apple.com",
  "ard.de",
  "ask.com",
  "bankofamerica.com",
  "berkeley.edu", // IPv6 enabled
  "biglobe.ne.jp", // IPv6 enabled
  "bing.com",
  "blogger.com", // IPv6 enabled
  "blogspot.com", // IPv6 enabled
  "cisco.com", // IPv6 enabled
  "cloudflare.com", // IPv6 enabled
  "cnet.com",
  "cnn.com",
  "comcast.com",
  "conduit.com",
  "costco.com",
  "craigslist.org",
  "creativecommons.org", // IPv6 enabled
  "deliciousdays.com", // IPv6 enabled
  "ebay.com",
  "ed.gov", // IPv6 enabled
  "edublogs.org", // IPv6 enabled
  "epa.gov", // IPv6 enabled
  "europa.eu", // IPv6 enabled
  "example.com", // IPv6 enabled
  "facebook.com", // IPv6 enabled
  "fedex.com",
  "feedburner.com", // IPv6 enabled
  "ford.com",
  "free.fr", // IPv6 enabled
  "friendfeed.com", // IPv6 enabled
  "g.co", // IPv6 enabled
  "ge.com",
  "go.com",
  "goo.gl", // IPv6 enabled
  "google.com", // IPv6 enabled
  "home.pl", // IPv6 enabled
  "hp.com",
//"hud.gov", // IPv6 enabled
  "imageshack.us",
  "imdb.com",
  "is.gd", // IPv6 enabled
  "java.com", // IPv6 enabled
  "linkedin.com",
  "live.com",
  "mail.ru",
  "mapy.cz", // IPv6 enabled
  "microsoft.com",
  "mit.edu", // IPv6 enabled
  "mozilla.org", // IPv6 enabled
  "msn.edu",
  "nih.gov", // IPv6 enabled
  "noaa.gov", // IPv6 enabled
  "oracle.com",
  "patch.com", // IPv6 enabled
  "paypal.com",
  "pen.io", // IPv6 enabled
  "photobucket.com",
  "php.net", // IPv6 enabled
  "pinterest.com",
  "reuters.com",
  "safeway.com",
//"si.edu", // IPv6 enabled
  "stackoverflow.com",
//"stanford.edu", // IPv6 enabled
  "state.gov", // IPv6 enabled
//"t-online.de", // IPv6 enabled
  "tagesschau.de",
  "tamu.edu", // IPv6 enabled
//"taobao.com",
  "tumblr.com",
  "twitter.com",
  "ucla.edu", // IPv6 enabled
  "unc.edu", // IPv6 enabled
  "uol.com.br", // IPv6 enabled
  "ups.com",
//"usa.gov", // IPv6 enabled
//"usgs.gov", // IPv6 enabled
  "usps.com",
  "va.gov", // IPv6 enabled
  "verizon.com",
//"vk.com", // IPv6 enabled
  "vkontakte.ru", // IPv6 enabled
//"volkswagen.de",
  "walmart.com",
  "web.de",
  "whitehouse.gov", // IPv6 enabled
  "wikimedia.org", // IPv6 enabled
  "wikipedia.org", // IPv6 enabled
  "wordpress.com",
  "yahoo.com", // IPv6 enabled
//"yandex.ru",
  "yolasite.com", // IPv6 enabled
  "youtube.com", // IPv6 enabled
};
static const int numHosts = sizeof(testHosts)/sizeof(char *);
static time_t lastPowercycle[2];
static time_t powercycleDelay[2];

#ifdef TRACING
static const int TRACEFD = 100;
static void TRACEap(const char *format, va_list ap) {
  size_t size = 80;
  char *buf = malloc(size);
  for (;;) {
    va_list ap1;
    va_copy(ap1, ap);
    ssize_t rc = vsnprintf(buf, size, format, ap1);
    va_end(ap1);
    if (rc < 0) {
      size = 0;
      break;
    } else if (rc == (ssize_t)size-1) {
      size = size < 4094 ? size*2 : size + 4096;
      char *ptr = realloc(buf, size);
      if (ptr) {
        buf = ptr;
      } else {
        size = rc;
        break;
      }
    } else {
      size = rc;
      break;
    }
  }
  if (size > 0) {
    if (buf[size-1] != '\n') {
      buf[size++] = '\n';
    }
    if (write(TRACEFD, buf, size)) {}
  }
  free(buf);
}
#endif
static void TRACE(const char *format, ...)
  __attribute__((format(printf, 1, 2)));
static void TRACE(const char *format, ...) {
#ifdef TRACING
  va_list ap;
  va_start(ap, format);
  TRACEap(format, ap);
  va_end(ap);
#endif
}

static void logMsg(int priority, const char *format, ...)
  __attribute__((format(printf, 2, 3)));
static void logMsg(int priority, const char *format, ...) {
  // Open syslog facility if not already done so.
  static int syslogIsOpen;
  if (!syslogIsOpen) {
    syslogIsOpen = 1;
    openlog("powerstrip", LOG_PID, LOG_DAEMON);
  }

  // Write message to syslog.
  va_list ap0, ap1;
  va_start(ap0, format);
#ifdef TRACING
  va_list ap2;
  va_copy(ap2, ap0);
  TRACEap(format, ap2);
  va_end(ap2);
#endif

  va_copy(ap1, ap0);
  vsyslog(priority, format, ap0);
  va_end(ap0);

  // If the program was configured for sending e-mail, spawn helper thread
  // unless we have already done so.
#if defined(emailUser)
  if (priority <= LOG_WARNING) {
    static FILE *logger;
    if (!logger) {
      int fds[2];
      if (pipe(fds)) {
        // Something went wrong. Skip this message but retry next time.
        return;
      }
      pid_t pid = fork();
      if (pid < 0) {
        // Something went wrong. Skip this message but retry next time.
        close(fds[0]);
        close(fds[1]);
        return;
      } else if (pid == 0) {
        // In child process
        close(fds[1]);
        alarm(0);

        // In a loop, read messages and send them by e-mail if we haven't
        // received any message in "flushMessageTimeout" seconds.
        int failedTries = 0;
        for (char *msg = NULL;;) {
          char buf[256];
          size_t len = 0;
          ssize_t rc = read(fds[0], buf, 1);
          if ((len = rc) == 1) {
            alarm(flushMessageTimeout);
            rc = read(fds[0], buf+1, sizeof(buf)-1);
            if (rc >= 0) {
              len += rc;
            }
          }
          if (rc <= 0) {
            if ((rc < 0 && errno == EINTR) ||
                (msg && (len == 0 || errno == EPIPE))) {
              // If the timeout expired, try to flush all pending messages.
              alarm(0);
              if (!msg) {
                // We don't actually have any message. This should never happen.
                goto mailFailed;
              }

#if !defined(mailServer)
              // If no mailserver was configure, connect to localhost instead.
              static const char mailServer[] = "localhost";
#endif
              struct addrinfo *res;
              struct addrinfo hints = { .ai_socktype = SOCK_STREAM,
                                        .ai_flags    = AI_ADDRCONFIG };
              if (getaddrinfo(mailServer, "smtp", &hints, &res) || !res) {
                // DNS failed (temporarily). Retry next time.
                goto mailFailed;
              }

              // Iterate through all possible addresses until we find one that
              // we can connect to.
              int fd;
              for (struct addrinfo *host = res; ;) {
                fd = socket(host->ai_family, host->ai_socktype,
                            host->ai_protocol);
                if (fd >= 0) {
                  if (!connect(fd, host->ai_addr, host->ai_addrlen)) {
                    TRACE("Connected to mail server");
                    break;
                  }
                  close(fd);
                }
                host = host->ai_next;
                if (!host) {
                  // Couldn't connect to any mail server. Retry next time.
                  freeaddrinfo(res);
                  TRACE("Couldn't connect to any mail servers");
                  goto mailFailed;
                }
              }
              freeaddrinfo(res);

              // Obtain the FQDN for the local machine.
              #if !defined(HOST_NAME_MAX)
              #define HOST_NAME_MAX 64
              #endif
              char hostname[HOST_NAME_MAX+1] = { 0 };
              char domainname[256] = { 0 };
              if (gethostname(hostname, sizeof(hostname)-1)) {
                strcpy(hostname, "localhost");
              }
              if (getdomainname(domainname, sizeof(domainname)-1) ||
                  !*domainname || !strcmp(domainname, "(none)")) {
                strcpy(domainname, "localdomain");
              }

              // Convert our file descriptor to a file handle. This should never
              // fail. But if it does, retry next time.
              FILE *smtp = fdopen(fd, "w");
              if (!smtp) {
                close(fd);
                continue;
              }

              // The subject line is made up of the very first log message in
              // the e-mail. Make sure to skip the time stamp, though.
              static const char prefix[] = "[powerstrip] ";
              char *subject = NULL;
              char *startPtr = strstr(msg, "    ");
              if (startPtr) {
                while (*startPtr == ' ') {
                  ++startPtr;
                }
                int subjectLen = strcspn(startPtr, "\r\n");
                if (subjectLen) {
                  subject = malloc(sizeof(prefix) + subjectLen);
                  if (subject) {
                    strcpy(subject, prefix);
                    memcpy(subject + sizeof(prefix) - 1, startPtr, subjectLen);
                    subject[sizeof(prefix) + subjectLen - 1] = '\000';
                  }
                }
              }

              // Format e-mail and submit it to the mail server.
              fprintf(smtp,
                      "EHLO %s.%s\r\n"
                      "MAIL FROM: <%s>\r\n"
                      "RCPT TO: <%s>\r\n"
                      "DATA\r\n"
                      "From: <%s>\r\n"
                      "To: <%s>\r\n"
                      "Subject: %s\r\n"
                      "\r\n"
                      "%s\r\n"
                      ".\r\n"
                      "QUIT\r\n",
                      hostname, domainname,
                      emailUser,
                      emailUser,
                      emailUser,
                      emailUser,
                      subject ? subject : "[powerstrip] Status message",
                      msg);

              // Done. We can now delete our buffered messages.
              fclose(smtp);
              free(subject);
              free(msg);
              msg = NULL;

            mailFailed:
              if (msg) {
                alarm(flushMessageTimeout);

                // If we haven't been able to deliver e-mail in several attempts,
                // drop the messages. Maybe, the mail server just doesn't work
                // at all.
                if (++failedTries >= 10) {
                  failedTries = 0;
                  free(msg);
                  msg = NULL;
                }
              }
              continue;
            }
            if (len == 0 || errno == EPIPE) {
              // The parent went away. Time for us to die.
              _exit(0);
            }
            continue;
          }

          // Extend the time that we wait for additional messages.
          alarm(flushMessageTimeout);

          // Append new message to the end of the currently buffered messages.
          char *newMsg = realloc(msg, (msg ? strlen(msg) : 0) + len + 1);
          if (newMsg == NULL) {
            // If we cannot buffer this message, just drop it.
            continue;
          }
          char *end = newMsg;
          if (msg) {
            end = strrchr(newMsg, '\000');
          }
          msg = newMsg;
          memcpy(end, buf, len);
          end[len] = '\000';
        }
      } else {
        // In parent process
        close(fds[0]);
        logger = fdopen(fds[1], "w");
        if (logger == NULL) {
          close(fds[1]);
          return;
        }
      }
    }

    // Send the log message and the current time stamp to the helper process.
    time_t tm = time(NULL);
    char *tmString = strdup(ctime(&tm));
    if (tmString) {
      *strrchr(tmString, '\n') = '\000';
      fprintf(logger, "%s        ", tmString);
      free(tmString);
    }
    vfprintf(logger, format, ap1);
    fprintf(logger, "\n");
    fflush(logger);
  }
#endif
  va_end(ap1);
}

struct cache {
  struct cache *left, *right;
  char            *host;
  int             family, socktype, protocol;
  socklen_t       addrlen;
  struct sockaddr addr;
};

static struct cache *findHost(const char *host, socklen_t addrlen) {
  static struct cache *root = NULL, **cache = &root;
  for (;;) {
    if (*cache == NULL) {
      *cache = calloc(1, sizeof(struct cache) + (addrlen > 0 ? addrlen : 0));
      (*cache)->host = strdup(host);
      break;
    } else {
      int cmp = strcasecmp(host, (*cache)->host);
      if (cmp == 0) {
        if (addrlen > 0) {
          *cache = realloc(*cache, sizeof(struct cache) + addrlen);
        }
        break;
      } else if (cmp < 0) {
        cache = &(*cache)->left;
      } else {
        cache = &(*cache)->right;
      }
    }
  }
  TRACE("findHost(\"%s\") -> %s", host,
        (*cache)->family == AF_INET6 ? "IPv6" :
        (*cache)->family == AF_INET  ? "IPv4" : "cache miss");
  return *cache;
}

// Returns >=0 on success and <0 on failure. If additional information is
// available, it returns 4, if the connection was made with IPv4 or 6 if made
// with IPv6. Return 46, if both IPv4 and IPv6 has successfully been tested.
// Returns -4 if the host could not be reached on the desired network, but would
// possibly have been reachable on IPv4. -6 if the host could not be reached on
// the desired network, but would possibly have been reachable on IPv6.
static int checkHosts(int mode, const char **hosts, int num, int tmo) {
  pid_t pids[num];
  memset(pids, 0, sizeof(pids));
  int fds[2];
  if (pipe(fds)) {
    return -1;
  }
  int running = 0;
  for (int i = 0; i < num; ++i) {
    pids[i] = fork();
    if (pids[i] < 0) {
      break;
    } else if (!pids[i]) {
      // In child process
      #ifndef AI_NUMERICSERV
      #define AI_NUMERICSERV 0
      #endif
      close(fds[0]);
      struct addrinfo *res = NULL, *host = NULL;
      struct addrinfo hints = { .ai_socktype = SOCK_STREAM,
                                .ai_flags    = AI_NUMERICSERV|
                                               AI_ADDRCONFIG,
                                .ai_family   = mode == 4 ? AF_INET :
                                               mode == 6 ? AF_INET6 :
                                                           AF_UNSPEC };
      int fd;
      if (getaddrinfo(hosts[i], "80", &hints, &res) || !res) {
        // Intermittend DNS failures are somewhat common and not
        // necessarily indicative of an overall network problem.
        // If available, try using cached DNS information until
        // DNS service starts working again.
        TRACE("getaddrinfo(\"%s\", AF_%s) -> failed",
              hosts[i], mode == 4 ? "INET" : mode == 6 ? "INET6" : "UNSPEC");
        res = NULL;
        struct cache *cached = findHost(hosts[i], 0);
        if (cached && cached->addrlen > 0) {
          if ((mode == 4 && cached->family != AF_INET) ||
              (mode == 6 && cached->family != AF_INET6)) {
            TRACE("Cache doesn't have a suitable entry either");
            _exit(mode == 4 ? 6 : mode == 6 ? 4 : 46);
          }
          if ((fd = socket(cached->family, cached->socktype,
                           cached->protocol)) < 0 ||
              connect(fd, &cached->addr, cached->addrlen) < 0) {
            _exit(1);
          }
        } else {
          TRACE("No cached entry found");
          _exit(1);
        }
      } else {
        TRACE("getaddrinfo(\"%s\", AF_%s) -> OK",
              hosts[i], mode == 4 ? "INET" : mode == 6 ? "INET6" : "UNSPEC");
        host = res;
        for (;;) {
          fd = socket(host->ai_family, host->ai_socktype, host->ai_protocol);
          if (fd >= 0) {
            if (!connect(fd, host->ai_addr, host->ai_addrlen)) {
              TRACE("Sucessfully connected to \"%s\" using IPv%d", hosts[i],
                    host->ai_family == AF_INET ? 4 : 6);
              break;
            }
            close(fd);
          }
          host = host->ai_next;
          if (!host) {
            if (res != NULL) {
              freeaddrinfo(res);
            }
            TRACE("No connection possible");
            _exit(1);
          }
        }
      }

      // It doesn't actually matter what response we get from the server.
      // The fact that we can connect at all is already a strong indicator
      // that the network works. And if we even receive a single byte for
      // our request, then we know for sure that we can send and receive data.
      static const char req0[] = "HEAD / HTTP/1.0\r\nHost: ";
      static const char req1[] = "\r\n\r\n";
      static struct iovec iov[] = {
        { .iov_base = (char *)req0, .iov_len = sizeof(req0)-1 },
        { .iov_base = 0,            .iov_len = 0              },
        { .iov_base = (char *)req1, .iov_len = sizeof(req1)-1 }
      };
      iov[1].iov_base = (char *)hosts[i];
      iov[1].iov_len  = strlen(hosts[i]);
      if (writev(fd, iov, 3) !=
          (ssize_t)(sizeof(req0)+sizeof(req1)-2+iov[1].iov_len)) {
        shutdown(fd, SHUT_RDWR);
        close(fd);
        if (res != NULL) {
          freeaddrinfo(res);
        }
        TRACE("Connected, but unresponsive");
        _exit(1);
      }
      char resp;
      ssize_t len = read(fd, &resp, 1);
      if (len <= 0) {
        shutdown(fd, SHUT_RDWR);
        close(fd);
        freeaddrinfo(res);
        TRACE("Connected, but unresponsive");
        _exit(1);
      }
      shutdown(fd, SHUT_RDWR);
      close(fd);

      // Update parent process with information about this host. It can
      // later be used as a cache for DNS data.
      if (res != NULL) {
        struct iovec info_iov[] = {
          { .iov_base = (char *)&i,                 .iov_len = sizeof(i) },
          { .iov_base = (char *)&host->ai_family,   .iov_len = sizeof(host->ai_family) },
          { .iov_base = (char *)&host->ai_socktype, .iov_len = sizeof(host->ai_socktype) },
          { .iov_base = (char *)&host->ai_protocol, .iov_len = sizeof(host->ai_protocol) },
          { .iov_base = (char *)&host->ai_addrlen,  .iov_len = sizeof(host->ai_addrlen) },
          { .iov_base = (char *) host->ai_addr,     .iov_len = host->ai_addrlen },
        };
        TEMP_FAILURE_RETRY(writev(fds[1], info_iov,
                                  sizeof(info_iov)/sizeof(*info_iov)));
        freeaddrinfo(res);
      }
      _exit(0);
    }
    ++running;
  }

  // Wait for at least one host to be alive or for the timeout to expire.
  // When either one happens, kill all the other processes (if any).
  close(fds[1]);
  int rc = -1;
  alarm(tmo);
  while (running > 0) {
    int status;
    pid_t pid = wait(&status);
    if (pid < 0) {
      goto kill;
    }

    // Read as many updated DNS records, as we can retrieve from our pipe.
    // This deals with the fact that not all child processes will update
    // DNS records at all times.
    struct hdr {
      int       idx, family, socktype, protocol;
      socklen_t addrlen;
    } hdr;
  next:;
    // Check whether any records are available. We do this by making
    // reads non-blocking.
    fcntl(fds[0], F_SETFL, fcntl(fds[0], F_GETFL) | O_NONBLOCK);
    size_t len = 0, needed = sizeof(hdr);
    for (char *ptr = (char *)&hdr; len < needed; ) {
      ssize_t readCount = read(fds[0], ptr + len, needed - len);
      if (readCount < 0 && errno == EINTR) {
        if (ptr != (char *)&hdr) {
          free(ptr);
        }
        goto kill;
      } else if ((readCount == 0 ||
                  (readCount < 0 && errno == EAGAIN)) && len == 0) {
        break;
      } else if (readCount > 0) {
        if (len == 0 && ptr == (char *)&hdr) {
          // Use blocking reads for the rest of the data.
          fcntl(fds[0], F_SETFL, fcntl(fds[0], F_GETFL) & ~O_NONBLOCK);
        }
        len += readCount;
        if (len == needed) {
          if (ptr == (char *)&hdr) {
            len    = 0;
            needed = hdr.addrlen;
            ptr    = calloc(1, needed);
          } else {
            // Update the DNS cache.
            struct cache *host = findHost(hosts[hdr.idx], hdr.addrlen);
            TRACE("Updating cache entry for \"%s\"", hosts[hdr.idx]);
            host->family   = hdr.family;
            host->socktype = hdr.socktype;
            host->protocol = hdr.protocol;
            host->addrlen  = hdr.addrlen;
            memcpy(&host->addr, ptr, hdr.addrlen);
            free(ptr);
            if (rc < 0) rc = 0;
            if (host->family == AF_INET ) rc = rc == 6 || rc == 46 ? 46 : 4;
            if (host->family == AF_INET6) rc = rc == 4 || rc == 46 ? 46 : 6;
            goto next;
          }
        }
      }
    }

    // Update the list of pids that we are still waiting for.
    for (int i = 0; i < num; ++i) {
      if (pid == pids[i]) {
        pids[i] = 0;
        --running;
        if (WIFEXITED(status) && !WEXITSTATUS(status)) {
          if (rc < 0) {
            rc = 0;
          }

          // Kill all other child processes that might have taken longer
          // to complete their task.
        kill:
          for (int j = 0; j < num; ++j) {
            if (pids[j] > 0) {
              kill(pids[j], SIGKILL);
            }
          }
        } else if (WIFEXITED(status) && num == 1) {
          if (WEXITSTATUS(status) == 4 || WEXITSTATUS(status) == 6) {
            rc = -WEXITSTATUS(status);
          }
        }
        break;
      }
    }
  }
  close(fds[0]);
  alarm(0);
  return rc;
}

static void switchPower(int state, int port) {
  TRACE("Switching power %s for %s", state ? "on" : "off",
        port ? "network switch" : "modem");
#ifdef serialPort
  int fd = TEMP_FAILURE_RETRY(open(serialPort, O_RDWR | O_NOCTTY | O_SYNC));
  if (fd < 0) {
  err0:
    logMsg(LOG_WARNING, "Unable to switch power %s. "
           "Maybe no suitable USB device is plugged in.",
           state ? "on" : "off");
    return;
  }
  struct termios tty = { 0 };
  if (TEMP_FAILURE_RETRY(tcgetattr(fd, &tty))) {
  err1:
    close(fd);
    goto err0;
  }

  // Open TTY with 1200 baud, 8N1, blocking reads and flush data.
  cfsetospeed(&tty, B1200);
  cfsetispeed(&tty, B1200);
  tty.c_cflag     = (tty.c_cflag & ~(CSIZE|PARENB|PARODD|CSTOPB|CRTSCTS)) |
                                     CS8|CLOCAL|CREAD;
  tty.c_iflag    &= ~(IGNBRK | IXON | IXOFF | IXANY);
  tty.c_lflag     = 0;
  tty.c_oflag     = 0;
  tty.c_cc[VMIN]  = 1;
  tty.c_cc[VTIME] = 5;
  if (TEMP_FAILURE_RETRY(tcsetattr(fd, TCSAFLUSH, &tty))) {
    goto err1;
  }

  // Change state and enable reporting of current status.
  if (TEMP_FAILURE_RETRY(write(fd, &("a(b(c(d("[4*state+2*port]), 2)) != 2) {
    goto err1;
  }
  TEMP_FAILURE_RETRY(tcdrain(fd));

  for (char ch;;) {
    // Read status. Status is reported as a sequence of eight "0" or "1"
    // characters. We care about the first or second character position, only.
    for (char nl = 0;;) {
      if (TEMP_FAILURE_RETRY(read(fd, &ch, sizeof(ch)) != 1)) {
        goto err1;
      }
      if (ch == '\r' || ch == '\n') {
        nl = 1;
      } else if (nl && (ch == '0' || ch == '1')) {
        if (port+1 == nl++) {
          char buf[7];
          for (size_t len = 0; len < sizeof(buf)-port;) {
            ssize_t rc = TEMP_FAILURE_RETRY(read(fd, buf + len,
                                                 sizeof(buf)-len-port));
            if (rc <= 0) {
              goto err1;
            }
            len += rc;
          }
          break;
        }
      } else {
        nl = 0;
      }
    }

    // Check if we actually need to do anything.
    if ((ch == '0') != state) {
      if (TEMP_FAILURE_RETRY(write(fd, &("abcd"[2*state+port]), sizeof(char)))
                             != sizeof(char)) {
        goto err1;
      }
      TEMP_FAILURE_RETRY(tcdrain(fd));
      continue;
    } else {
      break;
    }
  }

  // Disable reporting of current status, then close connection.
  if (TEMP_FAILURE_RETRY(write(fd, ")", 1)) != 1) { }
  TEMP_FAILURE_RETRY(tcdrain(fd));
  TEMP_FAILURE_RETRY(tcflush(fd, TCIFLUSH));
  close(fd);
#else
  pid_t pid = fork();
  if (pid < 0) {
    return;
  } else if (pid == 0) {
    struct usb_hub_descriptor {
      unsigned char bDescLength;
      unsigned char bDescriptorType;
      unsigned char bNbrPorts;
      unsigned char wHubCharacteristics[2];
      unsigned char bPwrOn2PwrGood;
      unsigned char bHubContrCurrent;
      unsigned char data[0];
    };

    // In child process
    usb_init();
    usb_find_busses();
    usb_find_devices();
    struct usb_bus *busses = usb_get_busses();
    if (busses == NULL) {
      _exit(1);
    }

    // Find all the hubs that claim to support power control. In practise,
    // many hubs claim to support either individual or ganged control, but
    // don't actually implement this feature. In particular, any of the
    // Intel chips commonly found on motherboards don't support any
    // power control. And external hubs either don't support it, or
    // advertise individual control but implement ganged control.
    //
    // As this data is so untrustworthy, we simply change the power settings
    // on every port that claims it can do so.
    int rc = 1;
    for (struct usb_bus *bus = busses; bus; bus = bus->next) {
      for (struct usb_device *dev = bus->devices; dev; dev = dev->next) {
        if (dev->descriptor.bDeviceClass != USB_CLASS_HUB) {
          continue;
        }
        usb_dev_handle *uh = usb_open(dev);
        if (uh) {
          unsigned char buf[1024];
          int len;
          struct usb_hub_descriptor *uhd = (struct usb_hub_descriptor *)buf;
          if ((len = usb_control_msg(uh,
                                     0x80 | USB_TYPE_CLASS | USB_RECIP_DEVICE,
                                     USB_REQ_GET_DESCRIPTOR, USB_DT_HUB << 8,
                                     0, (void *)uhd, sizeof(buf), 1000))
              > (int)sizeof(struct usb_hub_descriptor)) {
            if ((uhd->wHubCharacteristics[0] & 0x80) == 0 &&
                (uhd->wHubCharacteristics[0] & 0x03) >= 2) {
              continue;
            }
            for (int port = 1; port <= uhd->bNbrPorts; ++port) {
              if (usb_control_msg(uh, USB_TYPE_CLASS | USB_RECIP_OTHER, state ?
                                  USB_REQ_SET_FEATURE : USB_REQ_CLEAR_FEATURE,
                                  8, port, NULL, 0, 1000) >= 0) {
                rc = 0;
              }
            }
          }
          usb_close(uh);
        }
      }
    }
    _exit(rc);
  }
  int status;
  waitpid(pid, &status, 0);
  if (!WIFEXITED(status) || WEXITSTATUS(status)) {
    logMsg(LOG_WARNING, "Unable to switch power %s. "
           "Maybe no suitable USB device is plugged in.",
           state ? "on" : "off");
  }
#endif
}

static void networkFailed(int mode) {
  int idx = mode == 6;

  // Exponentially increase the time between attempts to power cycle the
  // networking equipment.
  time_t tm = time(NULL);
  if (lastPowercycle[idx] && tm - lastPowercycle[idx] < powercycleDelay[idx]) {
    return;
  }
  logMsg(LOG_WARNING,
         "Network appears to be down. %sPower cycling networking equipment",
         mode == 6 ? "This appears to affect IPv6 only! " : "");
  lastPowercycle[idx] = tm;
  if (!powercycleDelay[idx]) {
    powercycleDelay[idx] = minPowercycleDelay;
  } else {
    powercycleDelay[idx] *= 2;
    if (powercycleDelay[idx] > maxPowercycleDelay) {
      powercycleDelay[idx] = maxPowercycleDelay;
    }
  }
  switchPower(0, 0);
  sleep(powercycleTime);
  switchPower(1, 0);
}

static void alrm(int signo) {
}

// Checks if the network is currently accessible. Queries can be done for
// IPv4 (mode=4), IPv6 (mode=6) or both (mode=46). Updates idx, disabled, and
// skipping. Returns -1 in case of any type of error (this doesn't necessarily
// indicate whether the network actually is down, though!). Return a positive
// number, if network is OK. Might return 4, 6, or 46 if more details are
// available on whether a particular network type is available.
static int checkNetwork(int mode, int *idx, int *disabled, int *skipping) {
  // It is possible although unlikely that the network fails in a way that
  // all hosts have become disabled. This does not normally happen, as we
  // would typically detect that the entire network has disappeared and we
  // then no longer disable individual hosts.
  // But even if we did remove all hosts, that is OK. We will then loop
  // through all iterations until we have restored at least one host for
  // probing. This is slightly CPU inefficient, but the number of iterations
  // are bounded by maxDisabledIterations*numHosts, which is usually a
  // reasonably small number.
  for (;;) {
    *idx = (*idx + 1) % numHosts;

    // Skip disabled hosts for a couple of iterations
    if (!skipping[*idx] || !--skipping[*idx]) {
      break;
    }
  }
  TRACE("checkNetwork(AF_%s, \"%s\")",
        mode == 4 ? "INET" : mode == 6 ? "INET6" : "UNSPEC", testHosts[*idx]);

  int rc = checkHosts(mode, testHosts + *idx, 1, longHostTimeOut);
  if (rc < -1) {
    // This particular host cannot be reached with the given networking "mode".
    // (e.g. this might be a IPv4 only host, but we are requesting a IPv6
    // query).
    TRACE("Host \"%s\" cannot be reached on this network type",
          testHosts[*idx]);
    if (disabled[*idx]) {
      disabled[*idx] *= 2;
      if (disabled[*idx] > maxDisabledIterations) {
        disabled[*idx] = maxDisabledIterations;
      }
    } else {
      disabled[*idx] = 1;
    }
    skipping[*idx] = disabled[*idx];
    return -1;
  }

  if (rc < 0 &&
      checkHosts(mode, testHosts + *idx, 1, 2*longHostTimeOut) < 0 &&
      checkHosts(mode, testHosts + *idx, 1, 4*longHostTimeOut) < 0) {
    // If even a single host replies, we know that the network still works,
    // and we can ignore the failure of any other hosts.
    // As some hosts in our list might have died temporarily or even
    // permanently, upon encountering a failure we shuffle the remaining
    // lists of hosts, and test against an increasingly larger subset of
    // them. This gives a good trade-off between taking a long time to
    // detect network failure, and between needlessly hitting a large
    // number of hosts.
    //
    // Create list of hosts that we need to test against.
    int setSize = 0;
    const char *hosts[numHosts-1];
    memset(hosts, 0, sizeof(hosts));

    for (int i = 0; i < numHosts; ++i) {
      if (i == *idx) {
        continue;
      }
      if (!disabled[i]) {
        hosts[setSize++] = testHosts[i];
      }
    }

    // Shuffle lists of hosts
    for (int i = 0; i < setSize-1; ++i) {
      int swap = i + rand() % (setSize - i);
      const char *tmp = hosts[i];
      hosts[i] = hosts[swap];
      hosts[swap] = tmp;
    }

    // Test hosts
    for (int start = 0, step = 1; start < setSize; ) {
      if (start + step > setSize) {
        step = setSize-start;
      }
      if ((rc = checkHosts(mode, hosts + start, step, shortHostTimeOut)) >= 0) {
        // The network is still up, but one of our hosts is down.
        // Disable this host for an exponentially larger number of
        // iterations.
        if (disabled[*idx]) {
          disabled[*idx] *= 2;
          if (disabled[*idx] > maxDisabledIterations) {
            disabled[*idx] = maxDisabledIterations;
          }
        } else {
          if (mode == 46) {
            logMsg(LOG_NOTICE, "Network is up, but \"%s\" is unreachable",
                   testHosts[*idx]);
          }
          disabled[*idx] = 1;
        }
        skipping[*idx] = disabled[*idx];
        goto success;
      }

      // Double the number of hosts tested in parallel on each iteration.
      start += step;
      step  *= 2;
    }

    // Our network appears to be down
    networkFailed(mode);
    sleep(probeSleep);
    return -1;
  } else {
    if (disabled[*idx]) {
      logMsg(LOG_NOTICE, "Restored access to \"%s\"", testHosts[*idx]);
    }
    disabled[*idx] = 0;
    skipping[*idx] = 0;
  }
success:;
  // We have a working network
  int i = mode == 6;
  if (lastPowercycle[0] || lastPowercycle[i]) {
    logMsg(LOG_WARNING, "Network connectivity has been restored");
    if (system(
      "exec /usr/sbin/unbound-control reload </dev/null >/dev/null 2>&1")){}
  }
  lastPowercycle[0]  = lastPowercycle[i]  = 0;
  powercycleDelay[0] = powercycleDelay[i] = 0;

  return rc;
}

int main(int argc, char *argv[]) {
#ifdef TRACING
  dup2(2, TRACEFD);
#endif
  // Install a signal handler for SIGALRM. This signal handler doesn't actually
  // do anything. But having a signal handler means that upon receiving a
  // timeout from alarm(), any pending system call will return with EINTR.
  struct sigaction sa = { .sa_flags = 0 };
  sa.sa_handler = alrm;
  sigaction(SIGALRM, &sa, NULL);

  if ((argc >= 2 && argc <= 4) &&
      (strstr(argv[1], "cycle") ||
       !strcmp(argv[1], "on") || !strcmp(argv[1], "off"))) {
    int port = argc >= 3 && !!strstr(argv[2], "switch");
    int delay = argc >= 4 ? atoi(argv[3]) : 10;
    if (strstr(argv[1], "cycle") || !strcmp(argv[1], "off")) {
      switchPower(0, port);
    }
    if (strstr(argv[1], "cycle")) {
      sleep(delay);
    }
    if (strstr(argv[1], "cycle") || !strcmp(argv[1], "on")) {
      switchPower(1, port);
    }
    return 0;
  } else if (argc != 1) {
    fprintf(stderr, "Usage: %s [ cycle|on|off [ modem|switch [ delay ] ] ]\n",
            argv[0]);
    return 1;
  }

  signal(SIGPIPE, SIG_IGN);
  switchPower(1, 0);
  switchPower(1, 1);

  // This program is intended to be run as a system daemon. Don't write any
  // messages to stdout, but log all status updates to syslog.
  logMsg(LOG_NOTICE, "Starting powerstrip daemon");

  // Keep track of hosts that have been disabled because they have become
  // unresponsive. We record an exponentially increasing number of iterations
  // that these hosts are exempt from probing, and we also keep a counter of
  // how many iterations we are still skipping until the next probe.
  int idx46 = -1;
  #ifndef NOIPV6TESTS
  int idx6 = -1;
  #endif
  int disabled46[numHosts], disabled6[numHosts];
  int skipping46[numHosts], skipping6[numHosts];
  memset(disabled46, 0, sizeof(disabled46));
  memset(skipping46, 0, sizeof(skipping46));
  memset(disabled6,  0, sizeof(disabled6));
  memset(skipping6,  0, sizeof(skipping6));

  for (;;) {
    // We observe the IPv6 connectivity frequently goes down, even the modem
    // is otherwise working just fine. This gives a false reading, as many
    // hosts can be reached on both IPv4 and IPv6. So, we have to explicitly
    // check for IPv6 at all times.
    #ifndef NOIPV6TESTS
    int rc = checkNetwork(46, &idx46, disabled46, skipping46);
    if (rc != 6 && rc != 46) {
      for (int i = numHosts; --i; ) {
        if (checkNetwork(6, &idx6, disabled6, skipping6) >= 0) {
          break;
        }
      }
    }
    #else
    checkNetwork(4, &idx46, disabled46, skipping46);
    #endif
    #ifdef TRACING
    if (write(TRACEFD, "\n", 1)) {}
    #endif
    sleep(probeSleep);
  }
}
