/*
 * BonjourMDNSManager.cpp
 *
 *  Created on: Jan 15, 2016
 *      Author: Dmitri Rubinstein
 */

#include "MDNSManager.hpp"

#ifdef _WIN32
#include <process.h>
typedef int pid_t;
#define getpid _getpid
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "dnssd.lib")
#else
#include <sys/time.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netdb.h>
#endif

#include <dns_sd.h>
#include <thread>
#include <mutex>
#include <atomic>

#include <cerrno>
#include <cstring>
#include <cstddef>
#include <cassert>
#include <cstdint>
#include <cctype>
#include <memory>
#include <sstream>
#include <unordered_map>
#include <algorithm>
#include <utility>

#include <iostream>

namespace MDNS
{

namespace
{

typedef std::recursive_mutex ImplMutex;
typedef std::lock_guard<std::recursive_mutex> ImplLockGuard;

inline bool strEndsWith(const std::string &str, const std::string &strEnd)
{
    if (strEnd.size() > str.size())
        return false;
    if (strEnd.size() == str.size())
        return strEnd == str;
    std::string::const_reverse_iterator i = str.rbegin();
    std::string::const_reverse_iterator i1 = strEnd.rbegin();
    while (i1 != strEnd.rend())
    {
        if (*i != *i1)
            return false;
        ++i;
        ++i1;
    }
    return true;
}

inline void removeTrailingDot(std::string &str)
{
    if (str.length() > 0 && str[str.length()-1] == '.')
    {
        str.resize(str.length()-1);
    }
}

inline uint32_t toDnsSdInterfaceIndex(MDNSInterfaceIndex i)
{
    if (i == MDNS_IF_ANY)
    {
        return kDNSServiceInterfaceIndexAny;
    }
    return static_cast<uint32_t>(i);
}

inline MDNSInterfaceIndex fromDnsSdInterfaceIndex(uint32_t i)
{
    if (i == kDNSServiceInterfaceIndexAny)
    {
        return MDNS_IF_ANY;
    }
    return static_cast<MDNSInterfaceIndex>(i);
}


inline const char * toDnsSdStr(const std::string & str)
{
    return str.empty() ? 0 : str.c_str();
}

inline std::string fromDnsSdStr(const char *str)
{
    return str ? str : "";
}

std::string encodeTxtRecordData(const std::vector<std::string> & fields, bool & invalidFields)
{
    std::string str;
    invalidFields = false;

    for (auto it = fields.begin(), iend = fields.end(); it != iend; ++it)
    {
        if (it->length() > 255)
        {
            invalidFields = true;
            continue;
        }
        if (it->find_first_of('\0', 0) != std::string::npos)
        {
            invalidFields = true;
            continue;
        }

        str += (char)it->length();
        str += *it;
    }

    return str;
}

std::vector<std::string> decodeTxtRecordData(uint16_t txtLen, const unsigned char *txtRecord)
{
    std::vector<std::string> res;
    const unsigned char *cur = txtRecord;
    std::string::size_type i = 0;
    while (i < txtLen)
    {
        std::string::size_type len = static_cast<std::string::size_type>(*cur);
        if (len == 0)
            break;
        res.emplace_back(reinterpret_cast<const char*>(cur+1), len);
        cur += 1 + len;
        i += 1 + len;
    }
    return res;
}

std::string decodeDNSName(const std::string &str)
{
    std::string res;
    res.reserve(str.size()+2);
    for (std::string::const_iterator it = str.begin(), iend = str.end(); it != iend; ++it)
    {
        const char c = (*it);
        if (c == '\\')
        {
            if (++it == iend)
                break;
            const char c1 = *it;
            if (isdigit(c1))
            {
                if (++it == iend)
                    break;
                const char c2 = *it;
                if (isdigit(c2))
                {
                    if (++it == iend)
                        break;
                    const char c3 = *it;
                    if (isdigit(c3))
                    {
                        const char num[4] = {c1, c2, c3, '\0'};
                        res += static_cast<char>(atoi(num));
                    }
                    else
                    {
                        break;
                    }
                }
                else
                {
                    break;
                }
            }
            else
            {
                res += c1;
            }
        }
        else
        {
            res += c;
        }
    }
    return res;
}

const char * getDnsSdErrorName(DNSServiceErrorType error)
{
    switch (error)
    {
        case kDNSServiceErr_NoError: return "kDNSServiceErr_NoError";
        case kDNSServiceErr_Unknown: return "kDNSServiceErr_Unknown";
        case kDNSServiceErr_NoSuchName: return "kDNSServiceErr_NoSuchName";
        case kDNSServiceErr_NoMemory: return "kDNSServiceErr_NoMemory";
        case kDNSServiceErr_BadParam: return "kDNSServiceErr_BadParam";
        case kDNSServiceErr_BadReference: return "kDNSServiceErr_BadReference";
        case kDNSServiceErr_BadState: return "kDNSServiceErr_BadState";
        case kDNSServiceErr_BadFlags: return "kDNSServiceErr_BadFlags";
        case kDNSServiceErr_Unsupported: return "kDNSServiceErr_Unsupported";
        case kDNSServiceErr_NotInitialized: return "kDNSServiceErr_NotInitialized";
        case kDNSServiceErr_AlreadyRegistered: return "kDNSServiceErr_AlreadyRegistered";
        case kDNSServiceErr_NameConflict: return "kDNSServiceErr_NameConflict";
        case kDNSServiceErr_Invalid: return "kDNSServiceErr_Invalid";
        case kDNSServiceErr_Firewall: return "kDNSServiceErr_Firewall";
        case kDNSServiceErr_Incompatible: return "kDNSServiceErr_Incompatible";
        case kDNSServiceErr_BadInterfaceIndex: return "kDNSServiceErr_BadInterfaceIndex";
        case kDNSServiceErr_Refused: return "kDNSServiceErr_Refused";
        case kDNSServiceErr_NoSuchRecord: return "kDNSServiceErr_NoSuchRecord";
        case kDNSServiceErr_NoAuth: return "kDNSServiceErr_NoAuth";
        case kDNSServiceErr_NoSuchKey: return "kDNSServiceErr_NoSuchKey";
        case kDNSServiceErr_NATTraversal: return "kDNSServiceErr_NATTraversal";
        case kDNSServiceErr_DoubleNAT: return "kDNSServiceErr_DoubleNAT";
        case kDNSServiceErr_BadTime: return "kDNSServiceErr_BadTime";
        case kDNSServiceErr_BadSig: return "kDNSServiceErr_BadSig";
        case kDNSServiceErr_BadKey: return "kDNSServiceErr_BadKey";
        case kDNSServiceErr_Transient: return "kDNSServiceErr_Transient";
        case kDNSServiceErr_ServiceNotRunning: return "kDNSServiceErr_ServiceNotRunning";
        case kDNSServiceErr_NATPortMappingUnsupported: return "kDNSServiceErr_NATPortMappingUnsupported";
        case kDNSServiceErr_NATPortMappingDisabled: return "kDNSServiceErr_NATPortMappingDisabled";
        case kDNSServiceErr_NoRouter: return "kDNSServiceErr_NoRouter";
        case kDNSServiceErr_PollingMode: return "kDNSServiceErr_PollingMode";
        case kDNSServiceErr_Timeout: return "kDNSServiceErr_Timeout";
        case kDNSServiceErr_DefunctConnection: return "kDNSServiceErr_DefunctConnection";
        case kDNSServiceErr_PolicyDenied: return "kDNSServiceErr_PolicyDenied";
        case kDNSServiceErr_NotPermitted: return "kDNSServiceErr_NotPermitted";
        case kDNSServiceErr_StaleData: return "kDNSServiceErr_StaleData";
        default: return "Unknown";
    }
}

class DnsSdError: public MDNSError
{
public:
    using MDNSError::MDNSError;
};

} // unnamed namespace

class MDNSManager::PImpl
{
public:

    std::thread thread;
    ImplMutex mutex;
    std::atomic<bool> processEvents;
    DNSServiceRef connectionRef;

    struct RegisterARecord
    {
        DNSServiceRef serviceRef = nullptr;
        DNSRecordRef dnsRecordRef = nullptr;
        MDNSService::Id serviceId = MDNSService::NO_SERVICE;
        std::string hostName;
        MDNSManager::PImpl &pimpl;
        ErrorCodeHandler cb;

        RegisterARecord(const std::string &hostName, MDNSManager::PImpl &pimpl, ErrorCodeHandler cb)
                : hostName(hostName), pimpl(pimpl), cb(cb)
        { }

        /**
         * register callback
         */
        static void DNSSD_API registerARecordCB(
                DNSServiceRef                       sdRef,
                DNSRecordRef                        recRef,
                DNSServiceFlags                     flags,
                DNSServiceErrorType                 errorCode,
                void                                *context )
        {
            RegisterARecord *self = static_cast<RegisterARecord*>(context);

            //std::cerr << "REGISTER A-RECORD CALLBACK "<<self->hostName<<" EC "<<errorCode<<" FLAGS "<<flags<<" PTR "<<sdRef<<" self = "<<self<<std::endl;

            if (errorCode == kDNSServiceErr_NoError)
            {
                if (self->cb) {
                    self->cb(RegisterError::MDNSRegErr_NoError, {});
                }
            }
            else if (errorCode == kDNSServiceErr_NameConflict)
            {
                if (self->cb) {
                    self->cb(RegisterError::MDNSRegErr_NameConflict,
                             std::string("hostname already in use: ") + self->hostName);
                }
                self->pimpl.error(std::string("Register A record callback: name conflict!"));
            }
            else
            {
                if (self->cb) {
                    self->cb(RegisterError::MDNSRegErr_Unknown, getDnsSdErrorName(errorCode));
                }
                self->pimpl.error(std::string("Register A record callback: ")+getDnsSdErrorName(errorCode));
            }
        }
    };

    typedef std::unordered_map<MDNSService::Id, std::unique_ptr<RegisterARecord>> RegisterARecordMap;
    RegisterARecordMap registerARecordMap;

    struct RegisterRecord
    {
        DNSServiceRef serviceRef;
        MDNSService::Id serviceId;
        std::string serviceName;
        MDNSManager::PImpl &pimpl;

        RegisterRecord(const std::string &serviceName, MDNSManager::PImpl &pimpl)
            : serviceRef(0), serviceId(MDNSService::NO_SERVICE), serviceName(serviceName), pimpl(pimpl)
        { }

        /**
         * register callback
         */
        static void DNSSD_API registerCB(
            DNSServiceRef                       sdRef,
            DNSServiceFlags                     flags,
            DNSServiceErrorType                 errorCode,
            const char                          *name,
            const char                          *regtype,
            const char                          *domain,
            void                                *context )
        {
            // This is the asynchronous callback
            // Can be used to handle async. errors, get data from instantiated service or record references, etc.
            // Context is same pointer that was given to the callout
            // If registration was successful, errorCode = kDNSServiceErr_NoError
            RegisterRecord *self = static_cast<RegisterRecord*>(context);

            std::string serviceType = fromDnsSdStr(regtype);
            std::string serviceDomain = fromDnsSdStr(domain);

            // std::cerr << "REGISTER CALLBACK "<<name<<" EC "<<errorCode<<" FLAGS "<<flags<<" PTR "<<sdRef<<" self = "<<self<<std::endl;

            if (errorCode == kDNSServiceErr_NoError)
            {
                if (flags & kDNSServiceFlagsAdd)
                {
                    std::string newName = fromDnsSdStr(name);
                    if (self->serviceName != newName)
                    {
                        if (self->pimpl.alternativeServiceNameHandler)
                            self->pimpl.alternativeServiceNameHandler(newName, self->serviceName);
                    }
                }
                else
                {
                    removeTrailingDot(serviceType);
                    removeTrailingDot(serviceDomain);

                    self->pimpl.error(std::string("Could not register service '")+
                                      self->serviceName+"' (type: "+serviceType+", domain: "+serviceDomain+")");
                }
            }
            else
            {
                self->pimpl.error(std::string("Register callback: ")+getDnsSdErrorName(errorCode));
            }
        }

    };

    typedef std::unordered_map<MDNSService::Id, std::unique_ptr<RegisterRecord>> RegisterRecordMap;
    RegisterRecordMap registerRecordMap;

    struct BrowserRecord
    {
        MDNSServiceBrowser::Ptr handler;
        DNSServiceRef serviceRef;
        MDNSManager::PImpl &pimpl;

        BrowserRecord(const MDNSServiceBrowser::Ptr &handler, MDNSManager::PImpl &pimpl)
            : handler(handler), serviceRef(0), pimpl(pimpl)
        { }

        struct ResolveRecord
        {
            std::string type;
            std::string domain;
            BrowserRecord *parent;

            ResolveRecord(BrowserRecord *parent, std::string &&type, std::string &&domain)
                : type(std::move(type)), domain(std::move(domain)), parent(parent)
            {
            }
        };

        /**
         * browse callback
         */
        static void DNSSD_API browseCB(
                DNSServiceRef sdRef,
                DNSServiceFlags flags,
                uint32_t interfaceIndex,
                DNSServiceErrorType errorCode,
                const char *serviceName,
                const char *regtype,
                const char *replyDomain,
                void *context )
        {
            BrowserRecord *self = static_cast<BrowserRecord*>(context);

            std::string type = fromDnsSdStr(regtype);
            std::string domain = fromDnsSdStr(replyDomain);

            if (domain == ".")
            {
                // this browser response describes a service type

                if (self->handler)
                {
                    // remove trailing '.'
                    removeTrailingDot(type);

                    std::string::size_type i = type.find_last_of('.');
                    if (i != std::string::npos)
                    {
                        domain = type.substr(i+1);
                        type.resize(i);
                    }

                    type = fromDnsSdStr(serviceName)+"."+type;

                    if (flags & kDNSServiceFlagsAdd)
                    {
                        MDNSService service;
                        service.setInterfaceIndex(fromDnsSdInterfaceIndex(interfaceIndex));
                        service.setType(std::move(type));
                        service.setDomain(std::move(domain));

                        self->handler->onNewService(service);
                    }
                    else
                    {
                        self->handler->onRemovedService("", std::move(type), std::move(domain), fromDnsSdInterfaceIndex(interfaceIndex));
                    }
                }
            }
            else
            {
                // standard response
                if (flags & kDNSServiceFlagsAdd)
                {
                    std::unique_ptr<ResolveRecord> resrec(new ResolveRecord(self, std::move(type), std::move(domain)));
                    DNSServiceRef resolveRef = self->pimpl.connectionRef;
                    DNSServiceErrorType err =
                        DNSServiceResolve(&resolveRef,
                                          kDNSServiceFlagsShareConnection,
                                          interfaceIndex,
                                          serviceName,
                                          regtype,
                                          replyDomain,
                                          &resolveCB,
                                          resrec.get());

                    if (err == kDNSServiceErr_NoError)
                    {
                        resrec.release(); // resolveCB will delete ResolveRecord
                    }
                    else
                    {
                        self->pimpl.error(std::string("DNSServiceResolve: ")+getDnsSdErrorName(err));
                    }

                }
                else
                {
                    if (self->handler)
                    {
                        removeTrailingDot(type);
                        removeTrailingDot(domain);

                        self->handler->onRemovedService(serviceName, std::move(type), std::move(domain), fromDnsSdInterfaceIndex(interfaceIndex));
                    }
                }
            }
        }

        static void DNSSD_API resolveCB(DNSServiceRef sdRef,
                DNSServiceFlags flags,
                uint32_t interfaceIndex,
                DNSServiceErrorType errorCode,
                const char *fullname,
                const char *hosttarget,
                uint16_t port, /* In network byte order */
                uint16_t txtLen,
                const unsigned char *txtRecord,
                void *context )
        {
            ResolveRecord *rr = static_cast<ResolveRecord*>(context);
            BrowserRecord *self = static_cast<BrowserRecord*>(rr->parent);

            if (self->handler)
            {
                MDNSService service;
                service.setInterfaceIndex(fromDnsSdInterfaceIndex(interfaceIndex));

                std::string name = decodeDNSName(fromDnsSdStr(fullname));
                std::string suffix = std::string(".") + rr->type + rr->domain;
                std::string host = fromDnsSdStr(hosttarget);

                if (strEndsWith(name, suffix))
                {
                    name.resize(name.length()-suffix.length());
                }

                // remove trailing '.'
                removeTrailingDot(rr->type);
                removeTrailingDot(rr->domain);
                removeTrailingDot(host);

                int status;
                struct addrinfo hints;
                struct addrinfo *result;
                memset(&hints, 0, sizeof(hints));
                hints.ai_family = AF_INET;
                hints.ai_socktype = SOCK_STREAM;
                hints.ai_flags = AI_PASSIVE;
                if ((status = getaddrinfo(hosttarget, NULL, &hints, &result)) == 0 && result != NULL) {
                    if (result->ai_family == AF_INET) {
                        char address[INET_ADDRSTRLEN];
                        struct sockaddr_in* ipv4 = (struct sockaddr_in*)result->ai_addr;
                        if (NULL != inet_ntop(AF_INET, &(ipv4->sin_addr), address, INET_ADDRSTRLEN)) {
                            service.setAddress(std::string(address));
                        }
                    } else if (result->ai_family == AF_INET6) {
                        char address[INET6_ADDRSTRLEN];
                        struct sockaddr_in6* ipv6 = (struct sockaddr_in6*)result->ai_addr;
                        if (NULL != inet_ntop(AF_INET6, &(ipv6->sin6_addr), address, INET6_ADDRSTRLEN)) {
                            service.setAddress(std::string(address));
                        }
                    }
                    freeaddrinfo(result);
                }
                service.setName(std::move(name));
                service.setType(std::move(rr->type));
                service.setDomain(std::move(rr->domain));
                service.setHost(std::move(host));
                service.setPort(ntohs(port));
                service.setTxtRecords(decodeTxtRecordData(txtLen, txtRecord));

                self->handler->onNewService(service);
            }

            delete rr;

            DNSServiceRefDeallocate(sdRef);
        }

    };

    typedef std::unordered_multimap<MDNSServiceBrowser::Ptr, std::unique_ptr<BrowserRecord> > BrowserRecordMap;
    BrowserRecordMap browserRecordMap;

    struct QueryRecord
    {
        MDNSServiceBrowser::Ptr handler;
        DNSServiceRef serviceRef;
        MDNSManager::PImpl &pimpl;
        std::string fullname;

        QueryRecord(const MDNSServiceBrowser::Ptr &handler,
                    DNSServiceRef serviceRef,
                    MDNSManager::PImpl &pimpl,
                    const char* fullname)
            : handler(handler)
            , serviceRef(serviceRef)
            , pimpl(pimpl)
            , fullname(fullname)
        {
            // Empty
        }

        static void DNSSD_API queryCB(DNSServiceRef sdRef,
                                      DNSServiceFlags flags,
                                      uint32_t interfaceIndex,
                                      DNSServiceErrorType errorCode,
                                      const char *fullname,
                                      uint16_t rrtype,
                                      uint16_t rrclass,
                                      uint16_t rdlen,
                                      const void *rdata,
                                      uint32_t ttl,
                                      void *context)
        {
            if (errorCode != kDNSServiceErr_NoError)
                return;

            auto* self = static_cast<BrowserRecord*>(context);
            if (self && self->handler) {
                auto data = rdlen > 0 ? std::string(static_cast<const char*>(rdata), rdlen-1)
                                      : std::string{};

                self->handler->onQueryReply({
                    .fullname = fullname,
                    .interfaceIndex = fromDnsSdInterfaceIndex(interfaceIndex),
                    .rrtype = rrtype,
                    .rrclass = rrclass,
                    .data = data
                });
            }
        }
    };

    typedef std::unordered_multimap<MDNSServiceBrowser::Ptr, std::unique_ptr<QueryRecord>> QueryRecordMap;
    QueryRecordMap queryRecordMap;

    MDNSManager::AlternativeServiceNameHandler alternativeServiceNameHandler;
    MDNSManager::ErrorHandler errorHandler;
    std::vector<std::string> errorLog;

    PImpl()
        : thread(), mutex(), processEvents(true), connectionRef(0)
    {
        DNSServiceErrorType errorCode = DNSServiceCreateConnection(&connectionRef);

        if (errorCode != kDNSServiceErr_NoError)
            throw DnsSdError(std::string("DNSServiceCreateConnection: ")+getDnsSdErrorName(errorCode));
    }

    ~PImpl()
    {
        stop();
        DNSServiceRefDeallocate(connectionRef);
    }

    void eventLoop()
    {
        int fd;

        {
            ImplLockGuard g(mutex);
            fd = DNSServiceRefSockFD(connectionRef);
        }

        if (fd == -1)
        {
            error("DNSServiceRefSockFD: failed");
            return;
        }

        int nfds = fd + 1;
        fd_set readfds;
        struct timeval tv;
        DNSServiceErrorType err;

        while (processEvents)
        {
            // 1. Set up the fd_set as usual here.
            FD_ZERO(&readfds);

            // 2. Add the fd to the fd_set
            FD_SET(fd, &readfds);

            // 3. Set up the timeout.
            tv.tv_sec = 1; // wakes up every 1 sec if no socket activity occurs
            tv.tv_usec = 0;

            // wait for pending data or timeout to elapse:
            int result = select(nfds, &readfds, (fd_set*) 0, (fd_set*) 0, &tv);
            if (result > 0)
            {
                {
                    ImplLockGuard g(mutex);
                    err = kDNSServiceErr_NoError;
                    if (FD_ISSET(fd, &readfds))
                        err = DNSServiceProcessResult(connectionRef);
                }
                if (err != kDNSServiceErr_NoError)
                    error(std::string("DNSServiceProcessResult returned ")+getDnsSdErrorName(err));
            }
            else if (result == 0)
            {
                // timeout elapsed but no fd-s were signalled.
            }
            else
            {
                error(std::string("select() returned ")+std::to_string(result)+" errno "+
                      std::to_string(errno)+" "+strerror(errno));
            }

            std::this_thread::yield();
        }
    }

    void run()
    {
        if (thread.joinable())
        {
            throw MDNSError("MDNSManager already running");
        }
        processEvents = true;
        thread = std::move(std::thread(&PImpl::eventLoop, this));
    }

    void stop()
    {
        if (!thread.joinable())
        {
            return;
        }
        processEvents = false;
        thread.join();
    }

    void wait()
    {
        if (!thread.joinable())
        {
            return;
        }
        thread.join();
    }

    void error(std::string errorMsg)
    {
        ImplLockGuard g(mutex);

        if (errorHandler)
            errorHandler(errorMsg);
        errorLog.push_back(std::move(errorMsg));
    }

    void registerServiceBrowser(const MDNSServiceBrowser::Ptr & browser,
                                uint32_t interfaceIndex,
                                const char *dnsType,
                                const char *dnsDomain)
    {
        std::unique_ptr<BrowserRecord> brec(new BrowserRecord(browser, *this));

        brec->serviceRef = connectionRef;

        DNSServiceErrorType err =
            DNSServiceBrowse(&brec->serviceRef,
                             kDNSServiceFlagsShareConnection,
                             interfaceIndex,
                             dnsType,
                             dnsDomain,
                             &BrowserRecord::browseCB,
                             brec.get());

        if (err != kDNSServiceErr_NoError)
            throw DnsSdError(std::string("DNSServiceBrowse: ")+getDnsSdErrorName(err));

        browserRecordMap.insert(std::make_pair(brec->handler, std::move(brec)));
    }

    void registerServiceQuery(const MDNSServiceBrowser::Ptr& browser,
                              uint32_t interfaceIndex,
                              const char* fullname,
                              uint16_t rrtype,
                              uint16_t rrclass)
    {
        std::unique_ptr<QueryRecord> qrec(new QueryRecord(browser, connectionRef, *this, fullname));
        DNSServiceErrorType err =
            DNSServiceQueryRecord(&qrec->serviceRef,
                                  kDNSServiceFlagsShareConnection,
                                  interfaceIndex,
                                  fullname,
                                  rrtype,
                                  rrclass,
                                  &QueryRecord::queryCB,
                                  qrec.get());

        if (err != kDNSServiceErr_NoError)
            throw DnsSdError(std::string("DNSServiceQuery: ")+getDnsSdErrorName(err));

        queryRecordMap.insert(std::make_pair(qrec->handler, std::move(qrec)));
    }

};

MDNSManager::MDNSManager()
    : pimpl_(new MDNSManager::PImpl)
{
}

MDNSManager::~MDNSManager()
{
}

bool MDNSManager::isAvailable()
{
    return true;
}

void MDNSManager::run()
{
    pimpl_->run();
}

void MDNSManager::stop()
{
    pimpl_->stop();
}

void MDNSManager::wait()
{
    pimpl_->wait();
}

void MDNSManager::setAlternativeServiceNameHandler(MDNSManager::AlternativeServiceNameHandler handler)
{
    ImplLockGuard g(pimpl_->mutex);
    pimpl_->alternativeServiceNameHandler = handler;
}

void MDNSManager::setErrorHandler(MDNSManager::ErrorHandler handler)
{
    ImplLockGuard g(pimpl_->mutex);
    pimpl_->errorHandler = handler;
}

void MDNSManager::registerAddress(MDNSService &service,
                                  ErrorCodeHandler async_result)
{
    if (service.getId() != MDNSService::NO_SERVICE)
        throw MDNSError("Host address was already registered");

    if (service.getHost().empty() || service.getAddress().empty())
        throw MDNSError("hostname or address can't be empty");

    struct sockaddr_storage hostaddr;
    memset(&hostaddr, 0, sizeof(hostaddr));
    struct addrinfo *addrs = nullptr;
    if (getaddrinfo(service.getAddress().c_str(), nullptr, nullptr, &addrs) == 0 && addrs) {
        size_t addr_len = (addrs->ai_addr->sa_family == AF_INET6) ? sizeof(struct sockaddr_in6)
                                                                  : sizeof(struct sockaddr_in);
        memcpy(&hostaddr, addrs->ai_addr, addr_len);
    }
    if (addrs) {
        freeaddrinfo(addrs);
    }

    std::unique_ptr<MDNSManager::PImpl::RegisterARecord> arec(
            new MDNSManager::PImpl::RegisterARecord(service.getHost(), *pimpl_, std::move(async_result)));

    {
        ImplLockGuard g(pimpl_->mutex);

        DNSServiceRef sdRef = pimpl_->connectionRef;
        uint32_t ttl = 240;
        DNSServiceFlags flags = kDNSServiceFlagsShareConnection | kDNSServiceFlagsUnique;

        DNSServiceErrorType err;
        if (hostaddr.ss_family == AF_INET) {
            err = DNSServiceRegisterRecord(sdRef,
                                           &arec->dnsRecordRef,
                                           flags,
                                           toDnsSdInterfaceIndex(service.getInterfaceIndex()),
                                           service.getHost().c_str(),
                                           kDNSServiceType_A,
                                           kDNSServiceClass_IN,
                                           sizeof(struct in_addr),
                                           &((struct sockaddr_in *) &hostaddr)->sin_addr,
                                           ttl,
                                           &MDNSManager::PImpl::RegisterARecord::registerARecordCB,
                                           arec.get());
        } else if (hostaddr.ss_family == AF_INET6) {
            err = DNSServiceRegisterRecord(sdRef,
                                           &arec->dnsRecordRef,
                                           flags,
                                           toDnsSdInterfaceIndex(service.getInterfaceIndex()),
                                           service.getHost().c_str(),
                                           kDNSServiceType_AAAA,
                                           kDNSServiceClass_IN,
                                           sizeof(struct in6_addr),
                                           &((struct sockaddr_in6 *) &hostaddr)->sin6_addr,
                                           ttl,
                                           &MDNSManager::PImpl::RegisterARecord::registerARecordCB,
                                           arec.get());
        } else {
            err = kDNSServiceErr_BadParam;
        }

        if (err != kDNSServiceErr_NoError)
            throw DnsSdError(std::string("DNSServiceRegisterRecord: ") + getDnsSdErrorName(err));

        arec->serviceRef = sdRef;
        const MDNSService::Id serviceId = getNewServiceId();
        arec->serviceId = serviceId;
        setServiceId(service, serviceId);
        pimpl_->registerARecordMap.insert(std::make_pair(serviceId, std::move(arec)));
    }
}

void MDNSManager::unregisterAddress(MDNSService &service)
{
    if (service.getId() == MDNSService::NO_SERVICE)
        throw MDNSError("Service was not registered");

    ImplLockGuard g(pimpl_->mutex);

    const int flags = 0;
    auto it = pimpl_->registerARecordMap.find(service.getId());
    if (it != pimpl_->registerARecordMap.end())
    {
        // try and unregister, don't care about result
        DNSServiceRemoveRecord(it->second->serviceRef, it->second->dnsRecordRef, flags);
        // then remove our references
        pimpl_->registerARecordMap.erase(it);
        setServiceId(service, MDNSService::NO_SERVICE);
    }
}

void MDNSManager::registerService(MDNSService &service)
{
    if (service.getId() != MDNSService::NO_SERVICE)
        throw MDNSError("Service was already registered");

    bool invalidFields;
    std::string txtRecordData = encodeTxtRecordData(service.getTxtRecords(), invalidFields);
    if (invalidFields)
    {
        throw DnsSdError("Invalid fields in TXT record of service '"+service.getName()+"'");
    }

    std::unique_ptr<MDNSManager::PImpl::RegisterRecord> rrec(
        new MDNSManager::PImpl::RegisterRecord(service.getName(), *pimpl_));

    std::string serviceType = service.getType();
    if (!serviceType.empty())
    {
        for (auto it = service.getSubtypes().begin(), eit = service.getSubtypes().end();
             it != eit; ++it)
        {
            serviceType += "," + *it;
        }
    }

    {
        ImplLockGuard g(pimpl_->mutex);

        DNSServiceRef sdRef = pimpl_->connectionRef;

        DNSServiceErrorType err =
            DNSServiceRegister(&sdRef,
                               kDNSServiceFlagsShareConnection,
                               toDnsSdInterfaceIndex(service.getInterfaceIndex()),
                               service.getName().c_str(),
                               toDnsSdStr(serviceType),
                               toDnsSdStr(service.getDomain()),
                               toDnsSdStr(service.getHost()),
                               htons(service.getPort()),
                               static_cast<uint16_t>(txtRecordData.empty() ? 0 : txtRecordData.length()+1),
                               txtRecordData.empty() ? NULL : txtRecordData.c_str(),
                               &MDNSManager::PImpl::RegisterRecord::registerCB, // register callback
                               rrec.get());

        if (err != kDNSServiceErr_NoError)
            throw DnsSdError(std::string("DNSServiceRegister: ")+getDnsSdErrorName(err));

        rrec->serviceRef = sdRef;
        const MDNSService::Id serviceId = getNewServiceId();
        rrec->serviceId = serviceId;
        setServiceId(service, serviceId);
        pimpl_->registerRecordMap.insert(std::make_pair(serviceId, std::move(rrec)));
    }
}

void MDNSManager::updateService(MDNSService &service)
{
    unregisterService(service);
    registerService(service);
}

void MDNSManager::unregisterService(MDNSService &service)
{
    ImplLockGuard g(pimpl_->mutex);
    if (service.getId() == MDNSService::NO_SERVICE)
        throw MDNSError("Service was not registered");
    auto it = pimpl_->registerRecordMap.find(service.getId());
    if (it != pimpl_->registerRecordMap.end())
    {
        DNSServiceRefDeallocate(it->second->serviceRef);
        pimpl_->registerRecordMap.erase(it);
        setServiceId(service, MDNSService::NO_SERVICE);
    }
}

void MDNSManager::registerServiceBrowser(const MDNSServiceBrowser::Ptr & browser,
                                         MDNSInterfaceIndex interfaceIndex,
                                         const std::string &type,
                                         const std::vector<std::string> *subtypes,
                                         const std::string &domain,
                                         MDNSProto protocol) // not supported (yet)
{
    if (type.empty())
        throw MDNSError("type argument can't be empty");

    {
        ImplLockGuard g(pimpl_->mutex);

        if (subtypes)
        {
            std::string subtype;
            for (auto it = subtypes->begin(), eit = subtypes->end(); it != eit; ++it)
            {
                subtype = type;
                if (!it->empty())
                    subtype += ("," + *it);
                pimpl_->registerServiceBrowser(browser,
                                               toDnsSdInterfaceIndex(interfaceIndex),
                                               subtype.c_str(),
                                               toDnsSdStr(domain));
            }
        }
        else
        {
            pimpl_->registerServiceBrowser(browser,
                                           toDnsSdInterfaceIndex(interfaceIndex),
                                           type.c_str(),
                                           toDnsSdStr(domain));
        }
    }
}

void MDNSManager::unregisterServiceBrowser(const MDNSServiceBrowser::Ptr & browser)
{
    ImplLockGuard g(pimpl_->mutex);
    auto range = pimpl_->browserRecordMap.equal_range(browser);
    for (auto it = range.first, eit = range.second; it != eit; ++it)
    {
        DNSServiceRefDeallocate(it->second->serviceRef);
    }
    pimpl_->browserRecordMap.erase(browser);
}


void MDNSManager::registerServiceQuery(const MDNSServiceBrowser::Ptr& browser,
                                       MDNSInterfaceIndex interfaceIndex,
                                       const char* fullname,
                                       uint16_t rrtype,
                                       uint16_t rrclass)
{
    ImplLockGuard g(pimpl_->mutex);
    pimpl_->registerServiceQuery(browser,
                                 toDnsSdInterfaceIndex(interfaceIndex),
                                 fullname,
                                 rrtype,
                                 rrclass);
}

void MDNSManager::unregisterServiceQuery(const MDNSServiceBrowser::Ptr& browser, const char* fullname)
{
    ImplLockGuard g(pimpl_->mutex);
    auto range = pimpl_->queryRecordMap.equal_range(browser);
    for (auto it = range.first, eit = range.second; it != eit;)
    {
        if (fullname == "" || it->second->fullname == fullname)
        {
            DNSServiceRefDeallocate(it->second->serviceRef);
            it = pimpl_->queryRecordMap.erase(it);
        }
        else
        {
            ++it;
        }
    }
}


std::vector<std::string> MDNSManager::getErrorLog()
{
    std::vector<std::string> result;
    {
        ImplLockGuard g(pimpl_->mutex);
        result.swap(pimpl_->errorLog);
    }
    return result;
}

} // namespace MDNS
