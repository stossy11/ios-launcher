TARGET := iphone:clang:latest:15.0
ARCHS := arm64
include $(THEOS)/makefiles/common.mk

LIBRARY_NAME = AltStoreTweak

AltStoreTweak_FILES = Tweak.m
AltStoreTweak_CFLAGS = -fobjc-arc -DCONFIG_COMMIT=\"$(CONFIG_COMMIT)\"
AltStoreTweak_INSTALL_PATH = /Applications/Geode.app/Frameworks

include $(THEOS_MAKE_PATH)/library.mk
