#include "QtSnmpSubagent.h"
#include <QCoreApplication>
#include <QThread>
#include <QRegExp>
#include <QDebug>
#include <QStringList>
#include <QHostAddress>
#include <QDataStream>
#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>
#include <signal.h>

#ifndef QT_SNMP_SUBAGENT_DEBUG
    // TODO: disable qDebug()
    #define qDebug QNoDebug
#endif

namespace {
    QString getOidText( netsnmp_request_info*const request ) {
        QString result;
        const netsnmp_variable_list*const current_parameter = request->requestvb;
        for ( size_t i = 0; i < current_parameter->name_length; ++i ) {
            const oid part = current_parameter->name_loc[ i ];
            result += QString( ".%1" ).arg( part );
        }
        return result;
    }

    int delayed_instance_handler(
            netsnmp_mib_handler* handler,
            netsnmp_handler_registration* reginfo,
            netsnmp_agent_request_info* reqinfo,
            netsnmp_request_info* requests)
    {
        int res = SNMP_ERR_NOERROR;
        const QString oid_text = getOidText( requests );
        switch ( reqinfo->mode ) {
        case MODE_GET:
            qDebug() << "MODE_GET: " << oid_text;
            res = QtSnmpSubagent::instance()->agentCallbackGetValue( requests, oid_text );
            break;
        case MODE_SET_RESERVE1:
            qDebug() << "MODE_SET_RESERVE1: check type and size";
            res = QtSnmpSubagent::instance()->agentCallbackCheckTypeAndLen( requests, oid_text );
            break;
        case MODE_SET_RESERVE2:
            qDebug() << "MODE_SET_RESERVE2: check value";
            res = QtSnmpSubagent::instance()->agentCallbackCheckValue( requests, oid_text );
            break;
        case MODE_SET_ACTION:
            qDebug() << "MODE_SET_ACTION: apply changes( if error, undo will be called )";
            res = QtSnmpSubagent::instance()->agentCallbackApplyChange( requests, oid_text );
            break;
        case MODE_SET_COMMIT:
            qDebug() << "MODE_SET_COMMIT: complete action - final node";
            break;
        case MODE_SET_FREE:
            qDebug() << "MODE_SET_FREE: if reserve2 or reserve2 failed";
            break;
        case MODE_SET_UNDO:
            qDebug() << "MODE_SET_UNDO: if action failed";
            break;
        default:
            qDebug() << Q_FUNC_INFO << "unsupported mode:" << reqinfo->mode;
            res = netsnmp_call_next_handler(handler, reginfo, reqinfo, requests);
            break;
        }
        return res;
    }
}

QtSnmpSubagent* QtSnmpSubagent::instance() {
    static QtSnmpSubagent* subagent = nullptr;
    if ( not subagent ) {
        Q_ASSERT( qApp );
        QThread*const thread = new QThread;
        thread->setObjectName( "snmp_subagent" );
        subagent = new QtSnmpSubagent;
        subagent->moveToThread( thread );
        connect( qApp, SIGNAL( destroyed() ),
                 subagent, SLOT( deleteLater() ) );
        connect( subagent, SIGNAL( destroyed() ),
                 thread, SLOT( quit() ) );
        connect( thread, SIGNAL( finished() ),
                 thread, SLOT( deleteLater() ) );
        connect( thread, SIGNAL( started() ),
                 subagent, SLOT( start() ) );
        thread->start();
        for ( int i = 0; !subagent->m_initialized && (i < 1000); ++i ) {
            qApp->processEvents();
        }
    }
    return subagent;
}

bool QtSnmpSubagent::registerSnmpObject( const QtSnmpObjectDescription& description,
                                       const QVariant& value )
{
    bool ret_val = description.isValid();
    if ( ret_val ) {
        QtSnmpSubagent*const subagent = QtSnmpSubagent::instance();
        if ( ! subagent->m_parameters.contains( description.oid() ) ) {
            QList< oid > oid_list;
            foreach( const QString& part, description.oid().split( ".", QString::SkipEmptyParts ) ) {
                const oid val = part.toULong( &ret_val );
                if ( ret_val ) {
                    oid_list << val;
                } else {
                    qWarning() << Q_FUNC_INFO << "unable to parse oid:" << description.oid();
                    break;
                }
            }

            if ( ret_val ) {
                oid*const oid_array = new oid[ oid_list.count() ];
                for ( int i = 0; i < oid_list.count(); ++i ) {
                    oid_array[i] = oid_list.at( i );
                }

                netsnmp_handler_registration*const ads_b_handler =
                        netsnmp_create_handler_registration( qPrintable( description.oid() ),
                                                             delayed_instance_handler,
                                                             oid_array,
                                                             static_cast< size_t >(oid_list.count()),
                                                             HANDLER_CAN_RWRITE);
                const int res = netsnmp_register_instance( ads_b_handler );
                if ( MIB_REGISTERED_OK == res ) {
                    subagent->m_parameters.insert( description.oid(), Parameter( description, value ) );
                    qDebug() << "OID " << description.oid() << "successfully registered [" << value << "]";
                } else {
                    qWarning() << "unable to register OID " << description.oid();
                }
                memset( oid_array, 0, static_cast< size_t >( oid_list.size() ) );
                delete[] oid_array;
            }

        } else {
            qWarning() << Q_FUNC_INFO << "OID " << description.oid() << "already registered";
        }
    } else {
        qWarning() << Q_FUNC_INFO << "unable to register object with incorrect description:" << description;
    }
    return ret_val;
}

bool QtSnmpSubagent::unregisterSnmpObject( const QString& oid_text ) {
    bool ret_val = false;
    QtSnmpSubagent*const subagent = QtSnmpSubagent::instance();
    if ( subagent->m_parameters.contains( oid_text ) ) {

        QList< oid > oid_list;
        foreach( const QString& part, oid_text.split( ".", QString::SkipEmptyParts ) ) {
            const oid val = part.toULong( &ret_val );
            if ( ret_val ) {
                oid_list << val;
            } else {
                qWarning() << Q_FUNC_INFO << "unable to parse oid:" << oid_text;
                break;
            }
        }

        if ( ret_val ) {
            oid*const oid_array = new oid[ oid_list.count() ];
            for ( int i = 0; i < oid_list.count(); ++i ) {
                oid_array[i] = oid_list.at( i );
            }
            int res = unregister_mib( oid_array, static_cast< size_t >(oid_list.count()) );
            if ( MIB_UNREGISTERED_OK == res ) {
                subagent->m_parameters.remove( oid_text );
                qDebug() << "OID " << oid_text << "successfuly unregistred";
                ret_val = true;
            }
        }
    } else {
        qWarning() << Q_FUNC_INFO << "OID " << oid_text << " is not registered";
    }
    return ret_val;
}

QVariant QtSnmpSubagent::value( const QString& oid ) const {
    if ( m_initialized ) {
        const auto iter = m_parameters.constFind( oid );
        if ( m_parameters.constEnd() != iter ) {
            return iter->value;
        }
    }
    static QVariant empty;
    return empty;
}

void QtSnmpSubagent::setValue( const QString& oid_text, const QVariant& value ) {
    QHash< QString, Parameter >::iterator iter = m_parameters.find( oid_text );
    if ( m_parameters.end() != iter ) {
        if ( iter->description.checkValue( value ) ) {
            iter->value = value;
        } else {
            Q_ASSERT( false );
        }
    } else {
        qWarning() << Q_FUNC_INFO << "OID" << oid_text << "not registred";
        Q_ASSERT( false );
    }
}

void QtSnmpSubagent::start() {
    snmp_enable_stderrlog();
    netsnmp_ds_set_boolean( NETSNMP_DS_APPLICATION_ID, NETSNMP_DS_AGENT_ROLE, 1 );
    netsnmp_ds_set_string( NETSNMP_DS_APPLICATION_ID, NETSNMP_DS_AGENT_X_SOCKET, "tcp:localhost:705" );
    SOCK_STARTUP;
    init_agent( "lemz-ads-b-subagent" );
    init_snmp( "lemz-ads-b-subagent" );
    snmp_log( LOG_INFO, "lemz-ads-b-subagent is up and running.\n" );
    agent_check_and_process( 0 );
    startTimer( 100 );
    m_initialized = true;
}

int QtSnmpSubagent::agentCallbackGetValue( void*const pointer_to_request, const QString& oid_text ) {
    netsnmp_request_info*const request  = static_cast< netsnmp_request_info* >( pointer_to_request );
    QHash< QString, Parameter >::const_iterator iter = m_parameters.constFind( oid_text );
    if ( m_parameters.constEnd() != iter ) {
        switch ( iter->description.type() ) {
        case QtSnmpObjectDescription::TypeEnum:
        case QtSnmpObjectDescription::TypeInterger:
            {
                bool ok;
                const long int_value = iter->value.toInt( &ok );
                Q_ASSERT( ok );
                snmp_set_var_typed_value( request->requestvb,
                                          ASN_INTEGER,
                                          &int_value,
                                          sizeof( int_value ) );
            }
            break;
        case QtSnmpObjectDescription::TypeUnsigned:
            {
                bool ok;
                const long int_value = iter->value.toInt( &ok );
                Q_ASSERT( ok );
                snmp_set_var_typed_value( request->requestvb,
                                          ASN_UNSIGNED,
                                          &int_value,
                                          sizeof( int_value ) );
            }
            break;
        case QtSnmpObjectDescription::TypeReal:
            {
                bool ok;
                const double value = iter->value.toDouble( &ok );
                Q_ASSERT( ok );
                const QString text_value = QString::number( value, 'g', 9 );
                const QByteArray ba_value = text_value.toLocal8Bit();
                snmp_set_var_typed_value( request->requestvb,
                                          ASN_OCTET_STR,
                                          ba_value.constData(),
                                          static_cast< size_t >( ba_value.size() ) );
            }
            break;
        case QtSnmpObjectDescription::TypeIpAddress:
            {
                const QHostAddress address( iter->value.toString() );
                QByteArray ba_value;
                QDataStream stream( &ba_value, QIODevice::WriteOnly );
                stream.setVersion( QDataStream::Qt_4_5 );
                stream << address.toIPv4Address();
                snmp_set_var_typed_value( request->requestvb,
                                          ASN_IPADDRESS,
                                          ba_value.constData(),
                                          static_cast< size_t >( ba_value.size() ) );
            }
            break;
        case QtSnmpObjectDescription::TypeTimeTicks:
            {
                bool ok;
                const long int_value = iter->value.toInt( &ok );
                Q_ASSERT( ok );
                snmp_set_var_typed_value( request->requestvb,
                                          ASN_TIMETICKS,
                                          &int_value,
                                          sizeof( int_value ) );
            }
            break;
        case QtSnmpObjectDescription::TypeString:
            {
                const QByteArray ba_value = iter->value.toString().toLocal8Bit();
                snmp_set_var_typed_value( request->requestvb,
                                          ASN_OCTET_STR,
                                          ba_value.constData(),
                                          static_cast< size_t >( ba_value.size() ) );
            }
            break;
        default:
            qWarning() << Q_FUNC_INFO << "unsupported type:"
                       << static_cast< int >( iter->description.type() )
                       << " (" << oid_text << ")";
            break;
        }
    }
    return SNMP_ERR_NOERROR;
}

int QtSnmpSubagent::agentCallbackCheckTypeAndLen( void*const pointer_to_request, const QString& oid_text ) {
    QHash< QString, Parameter >::const_iterator iter = m_parameters.constFind( oid_text );
    if ( m_parameters.constEnd() != iter ) {
        netsnmp_request_info*const request  = static_cast< netsnmp_request_info* >( pointer_to_request );

        if ( iter->description.isReadOnly() ) {
            return SNMP_ERR_READONLY;
        }

        switch ( iter->description.type() ) {
        case QtSnmpObjectDescription::TypeEnum:
        case QtSnmpObjectDescription::TypeInterger:
            return netsnmp_check_vb_type_and_size(
                        request->requestvb,
                        ASN_INTEGER,
                        sizeof( request->requestvb->val.integer ) );
        case QtSnmpObjectDescription::TypeUnsigned:
            return netsnmp_check_vb_type_and_size(
                        request->requestvb,
                        ASN_UNSIGNED,
                        request->requestvb->val_len );
        case QtSnmpObjectDescription::TypeReal:
            return netsnmp_check_vb_type_and_size(
                        request->requestvb,
                        ASN_OCTET_STR,
                        request->requestvb->val_len );
        case QtSnmpObjectDescription::TypeIpAddress:
            return netsnmp_check_vb_type_and_size(
                        request->requestvb,
                        ASN_IPADDRESS,
                        request->requestvb->val_len );
        case QtSnmpObjectDescription::TypeTimeTicks:
            return netsnmp_check_vb_type_and_size(
                        request->requestvb,
                        ASN_TIMETICKS,
                        request->requestvb->val_len );
        case QtSnmpObjectDescription::TypeString:
            return netsnmp_check_vb_type_and_size(
                        request->requestvb,
                        ASN_OCTET_STR,
                        request->requestvb->val_len );
        default:
            qWarning() << Q_FUNC_INFO << "unsupported type:"
                       << static_cast< int >( iter->description.type() )
                       << " (" << oid_text << ")";
            break;
        }
        return SNMP_ERR_GENERR;
    }
    return SNMP_ERR_NOSUCHNAME;
}

int QtSnmpSubagent::agentCallbackCheckValue( void*const pointer_to_request, const QString& oid_text ) {
    bool res = false;
    QHash< QString, Parameter >::const_iterator iter = m_parameters.constFind( oid_text );
    if ( m_parameters.constEnd() != iter ) {
        netsnmp_request_info*const request  = static_cast< netsnmp_request_info* >( pointer_to_request );
        switch ( iter->description.type() ) {
        case QtSnmpObjectDescription::TypeEnum:
        case QtSnmpObjectDescription::TypeInterger:
            {
                long value = 0;
                memcpy( &value, request->requestvb->val.integer, request->requestvb->val_len );
                res = iter->description.checkValue( QVariant::fromValue( static_cast< int >( value ) ) );
            }
            break;
        case QtSnmpObjectDescription::TypeUnsigned:
            {
                long value = 0;
                memcpy( &value, request->requestvb->val.integer, request->requestvb->val_len );
                res = iter->description.checkValue( QVariant::fromValue( static_cast< unsigned >( value ) ) );
            }
            break;
        case QtSnmpObjectDescription::TypeReal:
            {
                char buffer[ BUFSIZ ];
                memset( buffer, 0, BUFSIZ );
                memcpy( buffer, request->requestvb->val.string, request->requestvb->val_len );
                const QString text_value = buffer;
                bool ok;
                const double value = text_value.toDouble( &ok );
                Q_ASSERT( ok );
                res = iter->description.checkValue( QVariant::fromValue( value ) );
            }
            break;
        case QtSnmpObjectDescription::TypeIpAddress:
            {
                long value = 0;
                memcpy( &value, request->requestvb->val.integer, request->requestvb->val_len );
                res = iter->description.checkValue( QVariant::fromValue( static_cast< unsigned >( value ) ) );
            }
            break;
        case QtSnmpObjectDescription::TypeTimeTicks:
            {
                long value = 0;
                memcpy( &value, request->requestvb->val.integer, request->requestvb->val_len );
                res = iter->description.checkValue( QVariant::fromValue( static_cast< int >( value ) ) );
            }
            break;
        case QtSnmpObjectDescription::TypeString:
            {
                char buffer[ BUFSIZ ];
                memset( buffer, 0, BUFSIZ );
                memcpy( buffer, request->requestvb->val.string, request->requestvb->val_len );
                const QString value = buffer;
                res = iter->description.checkValue( QVariant::fromValue( value ) );
            }
            break;
        default:
            qWarning() << Q_FUNC_INFO << "unsupported type:"
                       << static_cast< int >( iter->description.type() )
                       << " (" << oid_text << ")";
            Q_ASSERT( false );
            break;
        }
    }

    if ( ! res ) {
        return SNMP_ERR_BADVALUE;
    }

    return SNMP_ERR_NOERROR;
}

int QtSnmpSubagent::agentCallbackApplyChange( void*const pointer_to_request, const QString& oid_text ) {
    netsnmp_request_info*const request  = static_cast< netsnmp_request_info* >( pointer_to_request );
    QHash< QString, Parameter >::const_iterator iter = m_parameters.constFind( oid_text );
    if ( m_parameters.constEnd() != iter ) {
        switch ( iter->description.type() ) {
        case QtSnmpObjectDescription::TypeEnum:
        case QtSnmpObjectDescription::TypeInterger:
            {
                long value = 0;
                memcpy( &value, request->requestvb->val.integer, request->requestvb->val_len );
                emit snmpSetRequest( oid_text, QVariant::fromValue( static_cast< int >( value ) ) );
            }
            break;
        case QtSnmpObjectDescription::TypeUnsigned:
            {
                long value = 0;
                memcpy( &value, request->requestvb->val.integer, request->requestvb->val_len );
                emit snmpSetRequest( oid_text, QVariant::fromValue( static_cast< unsigned >( value ) ) );
            }
            break;
        case QtSnmpObjectDescription::TypeReal:
            {
                char buffer[ BUFSIZ ];
                memset( buffer, 0, BUFSIZ );
                memcpy( buffer, request->requestvb->val.string, request->requestvb->val_len );
                const QString text_value = buffer;
                bool ok;
                const double value = text_value.toDouble( &ok );
                Q_ASSERT( ok );
                emit snmpSetRequest( oid_text, QVariant::fromValue( value ) );
            }
            break;
        case QtSnmpObjectDescription::TypeIpAddress:
            {
                quint32 raw_value = 0;
                memcpy( &raw_value, request->requestvb->val.integer, request->requestvb->val_len );
                quint32 value = 0;
                const int size = sizeof( value );
                quint8* src = reinterpret_cast< quint8* >( &raw_value ) + ( size-1 );
                quint8* dst = reinterpret_cast< quint8* >( &value );
                for ( int i = 0; i < size; ++i ) {
                    *dst++ = *src--;
                }
                emit snmpSetRequest( oid_text, QVariant::fromValue( static_cast< unsigned >( value ) ) );
            }
            break;
        case QtSnmpObjectDescription::TypeTimeTicks:
            {
                long value = 0;
                memcpy( &value, request->requestvb->val.integer, request->requestvb->val_len );
                emit snmpSetRequest( oid_text, QVariant::fromValue( static_cast< int >( value ) ) );
            }
            break;
        case QtSnmpObjectDescription::TypeString:
            {
                char buffer[ BUFSIZ ];
                memset( buffer, 0, BUFSIZ );
                memcpy( buffer, request->requestvb->val.string, request->requestvb->val_len );
                const QString value = buffer;
                emit snmpSetRequest( oid_text, QVariant::fromValue( value ) );
            }
            break;
        default:
            qWarning() << Q_FUNC_INFO << "unsupported type:"
                       << static_cast< int >( iter->description.type() )
                       << " (" << oid_text << ")";
            Q_ASSERT( false );
            return SNMP_ERR_GENERR;
        }
    }
    return SNMP_ERR_NOERROR;
}

void QtSnmpSubagent::timerEvent( QTimerEvent* ) {
    agent_check_and_process( 0 );
}