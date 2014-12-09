EXTRA_DIST =     adapter_bbkanba.cc  
     
lib_LTLIBRARIES =     ecap_adapter_bbkanba.la
 
noinst_HEADERS =     bbkanba.h     debugger.h         autoconf.h
 
ecap_adapter_bbkanba_la_SOURCES = adapter_bbkanba.cc                                  debugger.cc
             
ecap_adapter_bbkanba_la_CPPFLAGS = $(LIBECAP_CFLAGS)
ecap_adapter_bbkanba_la_LDFLAGS = -module -avoid-version $(libecap_LIBS)
ecap_adapter_bbkanba_la_LIBADD= $(LIBECAP_LIBS)  -lboost_system -lboost_thread -lcppnetlib-uri -lcppnetlib-client-connections
 
 
DISTCLEANFILES =         autoconf.h
 
AM_CPPFLAGS = -I$(top_srcdir)/src
