PLUGIN_NAME=		pondsec-ndr
PLUGIN_VERSION=		0.1.0
PLUGIN_REVISION=	1
PLUGIN_COMMENT=		Behavioral Network Detection and Response for OPNsense
PLUGIN_DEPENDS=		${PYTHON_PKGNAMEPREFIX}sqlite3>0 ${PYTHON_PKGNAMEPREFIX}numpy>0
PLUGIN_MAINTAINER=	pondsec@users.noreply.github.com

.include "../../Mk/plugins.mk"
