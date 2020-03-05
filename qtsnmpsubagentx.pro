exists( $${PWD}/../config.pri ) : include($${PWD}/../config.pri)
QT = core network
TEMPLATE = lib
SOURCES_PATH = $${PWD}/src
HEADERS *= $${SOURCES_PATH}/*.h
SOURCES *= $${SOURCES_PATH}/*.cpp
win32 : !static : DEFINES *= BUILD_QTSNMPSUBAGENTX_DLL
