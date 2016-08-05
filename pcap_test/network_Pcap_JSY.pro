TEMPLATE = app
CONFIG += console
CONFIG -= app_bundle
CONFIG -= qt
CONFIG += console c++11

SOURCES += main.cpp

LIBS += -lpcap

HEADERS += \
    pcap_header.h
