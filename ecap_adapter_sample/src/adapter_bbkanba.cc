#include "bbkanba.h"
#include "debugger.h"
#include <iostream>
#include <algorithm>
#include <libecap/common/registry.h>
#include <libecap/common/errors.h>
#include <libecap/common/message.h>
#include <libecap/common/header.h>
#include <libecap/common/names.h>
#include <libecap/common/named_values.h>
#include <libecap/common/libecap.h>
#include <libecap/host/host.h>
#include <libecap/adapter/service.h>
#include <libecap/adapter/xaction.h>
#include <libecap/host/xaction.h>
#include <boost/network/uri.hpp>
#include <boost/network/uri/uri_io.hpp>
#include <boost/network/protocol/http/client.hpp>

using namespace boost::network;
// namespace http = boost::network::http;
 
namespace Adapter { // not required, but adds clarity
using   libecap::size_type;
typedef libecap::RequestLine *CLRLP;
 
class Service: public libecap::adapter::Service {
    public:
        // About
        virtual std::string uri() const; // unique across all vendors
        virtual std::string tag() const; // changes with version and config
        virtual void describe(std::ostream &os) const; // free-format info
 
        // Configuration
        virtual void configure(const libecap::Options &cfg);
        virtual void reconfigure(const libecap::Options &cfg);
 
        // Lifecycle
        virtual void start(); // expect makeXaction() calls
        virtual void stop(); // no more makeXaction() calls until start()
        virtual void retire(); // no more makeXaction() calls
 
        // Scope (XXX: this may be changed to look at the whole header)
        virtual bool wantsUrl(const char *url) const;
 
        // Work
        virtual libecap::adapter::Xaction *makeXaction(libecap::host::Xaction *hostx);
};
 
class Xaction: public libecap::adapter::Xaction {
    public:
        Xaction(libecap::shared_ptr<Service> s, libecap::host::Xaction *x);
        virtual ~Xaction();
 
        // meta-information for the host transaction
        virtual const libecap::Area option(const libecap::Name &name) const;
        virtual void visitEachOption(libecap::NamedValueVisitor &visitor) const;
 
        // lifecycle
        virtual void start();
        virtual void stop();
 
        // adapted body transmission control
        virtual void abDiscard();
        virtual void abMake();
        virtual void abMakeMore();
        virtual void abStopMaking();
 
        // adapted body content extraction and consumption
        virtual libecap::Area abContent(size_type offset, size_type size);
        virtual void abContentShift(size_type size);
 
        // virgin body state notification
        virtual void noteVbContentDone(bool atEnd);
        virtual void noteVbContentAvailable();
 
        // libecap::Callable API, via libecap::host::Xaction
        virtual bool callable() const;
 
    protected:
        void stopVb(); // stops receiving vb (if we are receiving it)
 
        void getUri(libecap::shared_ptr<libecap::Message> &);
        void goToUrl( std::string orgUrl,std::string host,std::string state);
        void debugAction(const std::string &action,const bool &showOrgUrl=true);
        libecap::host::Xaction *lastHostCall(); // clears hostx
 
    private:
        CLRLP requestLine;
        libecap::Area uri; // Request-URI from headers, for logging
        libecap::shared_ptr<const Service> service; // configuration access
        libecap::host::Xaction *hostx; // Host transaction rep
 
        typedef enum { opUndecided, opOn, opComplete, opNever } OperationState;
        typedef enum { localWebServer, normal } OprationAdaptedState;
        OperationState receivingVb;
        OperationState sendingAb;
        OprationAdaptedState adaptedGotoAction;
};
 
static const std::string CfgErrorPrefix =
    "eBBkanba Adapter: configuration error: ";
 
} // namespace Adapter
 
std::string Adapter::Service::uri() const {
    return "ecap://bbkanba.com/bbkanba";
}
 
std::string Adapter::Service::tag() const {
    return PACKAGE_VERSION;
}
 
void Adapter::Service::describe(std::ostream &os) const {
    os << "A eBBkanba adapter from " << PACKAGE_NAME << " v" << PACKAGE_VERSION;
}
 
void Adapter::Service::configure(const libecap::Options &cfg) {
}
 
void Adapter::Service::reconfigure(const libecap::Options &cfg) {
}
void Adapter::Service::start() {
    libecap::adapter::Service::start();
}
 
void Adapter::Service::stop() {
    libecap::adapter::Service::stop();
}
 
void Adapter::Service::retire() {
    libecap::adapter::Service::stop();
}
 
bool Adapter::Service::wantsUrl(const char *url) const {
    return true; // no-op is applied to all messages
}
 
libecap::adapter::Xaction *Adapter::Service::makeXaction(libecap::host::Xaction *hostx) {
    return new Adapter::Xaction(std::tr1::static_pointer_cast<Service>(self),hostx);
}
 
Adapter::Xaction::Xaction(libecap::shared_ptr<Service> aService,libecap::host::Xaction *x):
    service(aService),
    hostx(x),
    receivingVb(opUndecided),
    sendingAb(opUndecided),
    adaptedGotoAction(normal){
}
 
Adapter::Xaction::~Xaction() {
    if (libecap::host::Xaction *x = hostx) {
        hostx = 0;
        requestLine = 0;
        x->adaptationAborted();
    }
}
 
const libecap::Area Adapter::Xaction::option(const libecap::Name &) const {
    return libecap::Area(); // this transaction has no meta-information
}
 
void Adapter::Xaction::visitEachOption(libecap::NamedValueVisitor &) const {
    // this transaction has no meta-information to pass to the visitor
}
 
void Adapter::Xaction::start() {
    Must(hostx);

    static int scannerCount = 0;
    ++scannerCount;
    Debugger(ilNormal|flApplication) << "eBBkanba: " << "Initializing eBBkanba engine #" << scannerCount << ".";
 
    //查看请求是否包含http头以外的数据
    if (hostx->virgin().body()) {
        receivingVb = opOn;
        hostx->vbMake(); // ask host to supply virgin body
    } else {
        // we are not interested in vb if there is not one
        receivingVb = opNever;
    }
 
    //获取用户ip
    libecap::Header::Value clientIP = hostx->option(libecap::metaClientIp);
 
    /* adapt message header ,copy一份http请求的纯原始副本,然后下面可能会修改内容*/
    libecap::shared_ptr<libecap::Message> adapted = hostx->virgin().clone();
    Must(adapted != 0);
    // delete ContentLength header because we may change the length
    // unknown length may have performance implications for the host
    //获取用户请求的url
    getUri(adapted);
 
    if (uri.size > 0) {
        //adapted->header().removeAny(libecap::headerContentLength);
        uri::uri url_path(uri.toString());
        std::string url_path_tolower = url_path.host();
        std::transform(url_path_tolower.begin(), url_path_tolower.end(),url_path_tolower.begin(), ::tolower);
	printf("\r\nurl_path_tolower=%s\tclientIP=%s", url_path_tolower.c_str(), clientIP.toString().c_str());
        if (url_path_tolower.length() > 0 && url_path_tolower != "127.0.0.1" && clientIP.toString() != "") {
            std::string check;

		try
		{
			boost::network::http::client clnt;
			http::client::request request("http://127.0.0.1:9090/check.php?uip=" + clientIP.toString());
			http::client::response response;

			response = clnt.get(request);
			check = static_cast<std::string>(body(response));
		}
		catch (std::exception &e)
		{
			Debugger(ilNormal|flApplication) << "connect fail:" << e.what();
			check = "";
		}
//		catch (TextException &e2)
		{
//			check = "0";
		}
            if ( check == "0" ){
                //则表示用户没有经过认证
                goToUrl(uri.toString(),"http://127.0.0.1:9090","0");
            }
            if( check == "1" ){
                //表示已经过期
                goToUrl(uri.toString(),"http://127.0.0.1:9090","1");
            }
        }
    }
 
    // 最后返回我们修改过的用户请求
    if (!adapted->body()) {
        sendingAb = opNever; // there is nothing to send
        lastHostCall()->useAdapted(adapted);
    } else {
        hostx->useAdapted(adapted);
    }
}
 
void Adapter::Xaction::stop() {
    hostx = 0;
    requestLine = 0;
}
 
void Adapter::Xaction::abDiscard()
{
    Must(sendingAb == opUndecided); // have not started yet
    sendingAb = opNever;
    // we do not need more vb if the host is not interested in ab
    stopVb();
}
 
void Adapter::Xaction::abMake()
{
    Must(sendingAb == opUndecided); // have not yet started or decided not to send
    Must(hostx->virgin().body()); // that is our only source of ab content
 
    // we are or were receiving vb
    Must(receivingVb == opOn || receivingVb == opComplete);
     
    sendingAb = opOn;
    hostx->noteAbContentAvailable();
}
 
void Adapter::Xaction::abMakeMore()
{
    Must(receivingVb == opOn); // a precondition for receiving more vb
    hostx->vbMakeMore();
}
 
void Adapter::Xaction::abStopMaking()
{
    sendingAb = opComplete;
    // we do not need more vb if the host is not interested in more ab
    stopVb();
}
 
libecap::Area Adapter::Xaction::abContent(size_type offset, size_type size) {
    Must(sendingAb == opOn || sendingAb == opComplete);
    return hostx->vbContent(offset, size);
}
 
void Adapter::Xaction::abContentShift(size_type size) {
    Must(sendingAb == opOn || sendingAb == opComplete);
    hostx->vbContentShift(size);
}
 
void Adapter::Xaction::noteVbContentDone(bool atEnd)
{
    Must(receivingVb == opOn);
    receivingVb = opComplete;
    if (sendingAb == opOn) {
        hostx->noteAbContentDone(atEnd);
        sendingAb = opComplete;
    }
}
 
void Adapter::Xaction::noteVbContentAvailable()
{
    Must(receivingVb == opOn);
    if (sendingAb == opOn)
        hostx->noteAbContentAvailable();
}
 
bool Adapter::Xaction::callable() const {
    return hostx != 0; // no point to call us if we are done
}
 
// tells the host that we are not interested in [more] vb
// if the host does not know that already
void Adapter::Xaction::stopVb() {
    if (receivingVb == opOn) {
        hostx->vbStopMaking();
        receivingVb = opComplete;
    } else {
        // we already got the entire body or refused it earlier
        Must(receivingVb != opUndecided);
    }
}

//重新定位请求地址,到用户认证页面,并把用户请求url作为参数传入
void Adapter::Xaction::goToUrl(std::string orgUrl,std::string new_host, std::string state)
{
    std::string new_url_path = new_host + "/?state=" + state + "&orgUrl=" + orgUrl;
    const libecap::Header::Value new_url_path_r = libecap::Area::FromTempString(new_url_path);
    debugAction("new URL: " + new_url_path);
    requestLine->uri(new_url_path_r);
}

void Adapter::Xaction::getUri(libecap::shared_ptr<libecap::Message> &adapted)
{
    if (!hostx)
        return;
    if ( (requestLine = dynamic_cast<CLRLP>(&adapted->firstLine())) )
        uri = requestLine->uri();
}
 
void Adapter::Xaction::debugAction(const std::string &actDescript,const bool &showOrgUrl)
{
    std::string descipt (actDescript);
    if(showOrgUrl)
        descipt += " ( org URL: " + uri.toString() + " )";
//    Debugger(ilNormal|flApplication) << "eBBkanba: " << descipt ;
}
 
// this method is used to make the last call to hostx transaction
// last call may delete adapter transaction if the host no longer needs it
// TODO: replace with hostx-independent "done" method
libecap::host::Xaction *Adapter::Xaction::lastHostCall() {
    libecap::host::Xaction *x = hostx;
    Must(x);
    hostx = 0;
    requestLine = 0;
    return x;
}
 
// create the adapter and register with libecap to reach the host application
static const bool Registered = (libecap::RegisterService(new Adapter::Service), true);


