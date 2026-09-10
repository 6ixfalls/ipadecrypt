FINALPACKAGE := 1
THEOS_PACKAGE_COMPRESSION := gzip
TARGET := iphone:clang:latest:15.0
ARCHS := arm64 arm64e
THEOS_PACKAGE_SCHEME ?= rootless
INSTALL_TARGET_PROCESSES := SpringBoard

include $(THEOS)/makefiles/common.mk

TWEAK_NAME := IPADDecryptCompanion
IPADDecryptCompanion_FILES := Tweak.xm
IPADDecryptCompanion_FRAMEWORKS := Foundation UIKit
IPADDecryptCompanion_CFLAGS := -fobjc-arc -Wall -Wextra

TOOL_NAME := ipadc
ipadc_FILES := client.c
ipadc_CFLAGS := -Wall -Wextra
ipadc_INSTALL_PATH := /usr/bin

include $(THEOS_MAKE_PATH)/tweak.mk
include $(THEOS_MAKE_PATH)/tool.mk

after-install::
	install.exec "killall -9 SpringBoard"
