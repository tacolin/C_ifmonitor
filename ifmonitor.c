#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

#include <net/if.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <sys/epoll.h>

#define dprint(a, b...)  printf("[IF-MONITER][INFO] %s(): "a"\n", __func__, ##b)
#define derror(a, b...)  printf("[IF-MONITER][ERR ] %s(): "a"\n", __func__, ##b)

static int open_netlink(void)
{
    int fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (fd <= 0)
    {
        derror("socket create failed");
        return -1;
    }

    struct sockaddr_nl addr = {
        .nl_family = AF_NETLINK,
        .nl_pid    = getpid(),
        .nl_groups = RTMGRP_LINK | RTMGRP_IPV4_IFADDR | RTMGRP_IPV6_IFADDR,
    };

    if (bind(fd, (struct sockaddr*)&addr, sizeof(addr)) != 0)
    {
        derror("bind failed");
        close(fd);
        return -1;
    }

    return fd;
}

static int process_msg(struct sockaddr_nl *pAddr, struct nlmsghdr *pHdr)
{
    struct ifinfomsg* pIfi = NULL;
    struct ifaddrmsg* pIfa = NULL;
    int ifa_len = 0;
    struct rtattr *pRta    = NULL;

    char ifname[1024];
    switch (pHdr->nlmsg_type)
    {
        case RTM_NEWADDR:
            pIfa = NLMSG_DATA(pHdr);
            if_indextoname(pIfa->ifa_index, ifname);
            dprint("RTM_NEWADDR (%s)", ifname);

            pRta = IFA_RTA(pIfa);
            ifa_len = IFA_PAYLOAD(pHdr);
            for (; RTA_OK(pRta, ifa_len); pRta = RTA_NEXT(pRta, ifa_len))
            {
                char tmp[128];
                struct ifa_cacheinfo* pCache = NULL;

                switch (pRta->rta_type)
                {
                    case IFA_ADDRESS:
                        inet_ntop(pIfa->ifa_family, RTA_DATA(pRta), tmp, sizeof(tmp));
                        dprint("RTM_NEWADDR (%s): IFA_ADDRESS %s", ifname, tmp);
                        break;

                    case IFA_LOCAL:
                        inet_ntop(pIfa->ifa_family, RTA_DATA(pRta), tmp, sizeof(tmp));
                        dprint("RTM_NEWADDR (%s): IFA_LOCAL %s", ifname, tmp);
                        break;

                    case IFA_BROADCAST:
                        inet_ntop(pIfa->ifa_family, RTA_DATA(pRta), tmp, sizeof(tmp));
                        dprint("RTM_NEWADDR (%s): IFA_BROADCAST %s", ifname, tmp);
                        break;

                    case IFA_ANYCAST:
                        inet_ntop(pIfa->ifa_family, RTA_DATA(pRta), tmp, sizeof(tmp));
                        dprint("RTM_NEWADDR (%s): IFA_ANYCAST %s", ifname, tmp);
                        break;

                    case IFA_LABEL:
                        strncpy(tmp, RTA_DATA(pRta), sizeof(tmp));
                        dprint("RTM_NEWADDR (%s): IFA_LABEL %s", ifname, tmp);
                        break;

                    case IFA_CACHEINFO:
                        pCache = RTA_DATA(pRta);
                        dprint("RTM_NEWADDR (%s): IFA_CACHEINFO prefered = %u", ifname, pCache->ifa_prefered);
                        dprint("RTM_NEWADDR (%s): IFA_CACHEINFO valid    = %u", ifname, pCache->ifa_valid);
                        dprint("RTM_NEWADDR (%s): IFA_CACHEINFO cstamp   = %u", ifname, pCache->cstamp);
                        dprint("RTM_NEWADDR (%s): IFA_CACHEINFO tstamp   = %u", ifname, pCache->tstamp);
                        break;

                    case IFA_FLAGS:
                        dprint("RTM_NEWADDR (%s): IFA_FLAGS 0x%x", ifname, (uint32_t)RTA_DATA(pRta));
                        break;

                    default:
                        dprint("other rta_type = %d", pRta->rta_type);
                        break;
                }
            }
            break;

        case RTM_DELADDR:
            pIfa = NLMSG_DATA(pHdr);
            if_indextoname(pIfa->ifa_index, ifname);
            dprint("RTM_DELADDR (%s)", ifname);
            break;

        case RTM_NEWLINK:
            pIfi = NLMSG_DATA(pHdr);
            if_indextoname(pIfi->ifi_index, ifname);
            dprint("RTM_NEWLINK (%s) : %s", ifname, (pIfi->ifi_flags & IFF_RUNNING) ? "RUNNING" : "NOT-RUNNING");
            break;

        case RTM_DELLINK:
            pIfi = NLMSG_DATA(pHdr);
            if_indextoname(pIfi->ifi_index, ifname);
            dprint("RTM_DELLINK (%s)", ifname);
            break;

        default:
            dprint("other nlmsg_type = %d", pHdr->nlmsg_type);
            break;
    }

    return 0;
}

static void recv_netlink(int fd)
{
    uint8_t buffer[65535] = {0};

    struct iovec iov = {};
    iov.iov_base = buffer;
    iov.iov_len  = sizeof(buffer);

    struct sockaddr_nl addr = {};
    struct msghdr msg  = {};
    msg.msg_name       = &addr;
    msg.msg_namelen    = sizeof(addr);
    msg.msg_iov        = &iov;
    msg.msg_iovlen     = 1;
    msg.msg_control    = NULL;
    msg.msg_controllen = 0;
    msg.msg_flags      = 0;

    int status = recvmsg(fd, &msg, 0);
    if (status < 0)
    {
        derror("Error recvmsg: %d", status);
        return;
    }
    else if (status == 0)
    {
        dprint("EOF");
        return;
    }

    struct nlmsghdr* pHdr = NULL;
    for (pHdr = (struct nlmsghdr*)buffer; NLMSG_OK(pHdr, (unsigned int)status); pHdr = NLMSG_NEXT(pHdr, status))
    {
        if (pHdr->nlmsg_type == NLMSG_DONE)
        {
            dprint("NLMSG_DONE");
            return;
        }
        else if (pHdr->nlmsg_type == NLMSG_ERROR)
        {
            derror("Message is an error - decode TBD");
            return;
        }

        int ret = process_msg(&addr, pHdr);
        if (ret < 0)
        {
            derror("process_msg failed");
            return;
        }
    }
    return;
}

int main(int argc, char const *argv[])
{
    int epfd = epoll_create(10);
    if (epfd <= 0)
    {
        derror("epoll_create failed");
        return -1;
    }

    int fd = open_netlink();
    if (fd <= 0)
    {
        derror("open_netlink failed");
        return -1;
    }

    struct epoll_event ev = {};
    ev.data.fd = fd;
    ev.events = EPOLLIN;
    epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &ev);

    dprint("[%s] is running\n", argv[0]);

    while (1)
    {
        struct epoll_event evbuf[10];
        int ev_num = epoll_wait(epfd, evbuf, 10, -1);
        int i;
        for (i=0; i<ev_num; i++)
        {
            if (evbuf[i].events & EPOLLIN)
            {
                if (evbuf[i].data.fd == fd)
                {
                    recv_netlink(evbuf[i].data.fd);
                }
            }
        }
    }
    close(fd);
    close(epfd);
    return 0;
}
