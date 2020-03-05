#pragma once

#include <QObject>
#include "QtSnmpObjectDescription.h"
#include <QHash>
#include "win_export.h"

class WIN_EXPORT QtSnmpSubagent : public QObject {
    Q_OBJECT
    Q_DISABLE_COPY( QtSnmpSubagent )
    explicit QtSnmpSubagent( QObject*const parent = nullptr ) : QObject(parent) {}

public:
    static QtSnmpSubagent* instance();

    bool registerSnmpObject( const QtSnmpObjectDescription&, const QVariant& value );
    bool unregisterSnmpObject( const QString& oid );

    QVariant value( const QString& oid ) const;
    Q_SLOT void setValue( const QString& oid, const QVariant& value );

    Q_SIGNAL void snmpSetRequest( const QString& oid, const QVariant& value );

    Q_SLOT void start();

    int agentCallbackGetValue( void*const request, const QString& oid );
    int agentCallbackCheckTypeAndLen( void*const request, const QString& oid );
    int agentCallbackCheckValue( void*const request, const QString& oid );
    int agentCallbackApplyChange( void*const request, const QString& oid );
private:
    virtual void timerEvent( QTimerEvent* ) override final;

private:
    bool m_initialized = false;

    struct Parameter {
        QtSnmpObjectDescription description;
        QVariant value;

        Parameter( const QtSnmpObjectDescription& _description,
                   const QVariant& _value )
            : description( _description )
            , value( _value )
        {
        }
    };

    QHash< QString, Parameter > m_parameters;
};
