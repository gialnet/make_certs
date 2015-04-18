#
# Generated Makefile - do not edit!
#
# Edit the Makefile in the project folder instead (../Makefile). Each target
# has a -pre and a -post target defined where you can add customized code.
#
# This makefile implements configuration specific macros and targets.


# Environment
MKDIR=mkdir
CP=cp
GREP=grep
NM=nm
CCADMIN=CCadmin
RANLIB=ranlib
CC=cc
CCC=CC
CXX=CC
FC=f95
AS=as

# Macros
CND_PLATFORM=OracleSolarisStudio-Solaris-x86
CND_DLIB_EXT=so
CND_CONF=Debug
CND_DISTDIR=dist
CND_BUILDDIR=build

# Include project Makefile
include Makefile

# Object Directory
OBJECTDIR=${CND_BUILDDIR}/${CND_CONF}/${CND_PLATFORM}

# Object Files
OBJECTFILES= \
	${OBJECTDIR}/certexport.o \
	${OBJECTDIR}/certsign.o \
	${OBJECTDIR}/genrequest.o \
	${OBJECTDIR}/main.o \
	${OBJECTDIR}/serial.o


# C Compiler Flags
CFLAGS=

# CC Compiler Flags
CCFLAGS=
CXXFLAGS=

# Fortran Compiler Flags
FFLAGS=

# Assembler Flags
ASFLAGS=

# Link Libraries and Options
LDLIBSOPTIONS=-lcrypto -lssl -Bstatic

# Build Targets
.build-conf: ${BUILD_SUBPROJECTS}
	"${MAKE}"  -f nbproject/Makefile-${CND_CONF}.mk ${CND_DISTDIR}/${CND_CONF}/${CND_PLATFORM}/mkcertmyempresa

${CND_DISTDIR}/${CND_CONF}/${CND_PLATFORM}/mkcertmyempresa: ${OBJECTFILES}
	${MKDIR} -p ${CND_DISTDIR}/${CND_CONF}/${CND_PLATFORM}
	${LINK.c} -o ${CND_DISTDIR}/${CND_CONF}/${CND_PLATFORM}/mkcertmyempresa ${OBJECTFILES} ${LDLIBSOPTIONS}

${OBJECTDIR}/certexport.o: certexport.c 
	${MKDIR} -p ${OBJECTDIR}
	$(COMPILE.c) -g -o ${OBJECTDIR}/certexport.o certexport.c

${OBJECTDIR}/certsign.o: certsign.c 
	${MKDIR} -p ${OBJECTDIR}
	$(COMPILE.c) -g -o ${OBJECTDIR}/certsign.o certsign.c

${OBJECTDIR}/genrequest.o: genrequest.c 
	${MKDIR} -p ${OBJECTDIR}
	$(COMPILE.c) -g -o ${OBJECTDIR}/genrequest.o genrequest.c

${OBJECTDIR}/main.o: main.c 
	${MKDIR} -p ${OBJECTDIR}
	$(COMPILE.c) -g -o ${OBJECTDIR}/main.o main.c

${OBJECTDIR}/serial.o: serial.c 
	${MKDIR} -p ${OBJECTDIR}
	$(COMPILE.c) -g -o ${OBJECTDIR}/serial.o serial.c

# Subprojects
.build-subprojects:

# Clean Targets
.clean-conf: ${CLEAN_SUBPROJECTS}
	${RM} -r ${CND_BUILDDIR}/${CND_CONF}
	${RM} ${CND_DISTDIR}/${CND_CONF}/${CND_PLATFORM}/mkcertmyempresa

# Subprojects
.clean-subprojects:

# Enable dependency checking
.dep.inc: .depcheck-impl

include .dep.inc
