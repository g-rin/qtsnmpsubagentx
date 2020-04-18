#include "QtSnmpObjectDescription.h"
#include <QRegExp>
#include <QDebug>
#include <QHostAddress>
#include <math.h>

QtSnmpObjectDescription::QtSnmpObjectDescription( const QString& oid, const Type type )
    : m_oid( oid )
    , m_type( type )
{
}

bool QtSnmpObjectDescription::isValid() const {
    bool res = QRegExp( "(\\.\\d+)+" ).exactMatch( m_oid );
    switch ( m_type ) {
    case TypeInterger:
        res = res && !hasAvailableValues();
        break;
    case TypeEnum:
        res = res && hasAvailableValues();
        res = res && !hasLimits();
        res = res && !hasStep();
        break;
    case TypeUnsigned:
    case TypeCounter:
    case TypeGauge:
        res = res && !hasAvailableValues();
        break;
    case TypeReal:
        res = res && !hasAvailableValues();
        break;
    case TypeIpAddress:
        res = res && !hasAvailableValues();
        res = res && !hasLimits();
        res = res && !hasStep();
        break;
    case TypeTimeTicks:
        res = res && !hasAvailableValues();
        res = res && !hasLimits();
        res = res && !hasStep();
        break;
    case TypeString:
        res = res && !hasAvailableValues();
        res = res && !hasLimits();
        res = res && !hasStep();
        break;
    default:
        break;
    }
    return res;
}

QString QtSnmpObjectDescription::oid() const {
    return m_oid;
}

QtSnmpObjectDescription::Type QtSnmpObjectDescription::type() const {
    return m_type;
}

static QDebug operator<<( QDebug stream, const QtSnmpObjectDescription::Type type ) {
    switch ( type ) {
    case QtSnmpObjectDescription::TypeInterger:
        stream << "TypeInterger";
        break;
    case QtSnmpObjectDescription::TypeEnum:
        stream << "TypeEnum";
        break;
    case QtSnmpObjectDescription::TypeUnsigned:
        stream << "TypeUnsigned";
        break;
    case QtSnmpObjectDescription::TypeCounter:
        stream << "TypeCounter";
        break;
    case QtSnmpObjectDescription::TypeGauge:
        stream << "TypeGauge";
        break;
    case QtSnmpObjectDescription::TypeReal:
        stream << "TypeReal";
        break;
    case QtSnmpObjectDescription::TypeIpAddress:
        stream << "TypeIpAddress";
        break;
    case QtSnmpObjectDescription::TypeTimeTicks:
        stream << "TypeTimeTicks";
        break;
    case QtSnmpObjectDescription::TypeString:
        stream << "TypeString";
        break;
    default:
        stream << "unsupported: " << static_cast< int >( type );
        break;
    }
    return  stream;
}

bool QtSnmpObjectDescription::checkValue( const QVariant& value ) const {
    bool res = false;
    switch ( m_type ) {
    case TypeInterger:
        res = value.canConvert( QVariant::Int );
        if ( res && hasLimits() ) {
            const int val = value.toInt();
            const int min = mininum().toInt( &res );
            res = res && ( val >= min );
            if ( not res ) {
                return false;
            }

            const int max = maximum().toInt( &res );
            res = res && ( val <= max );
            if ( not res ) {
                return false;
            }

            if ( hasStep() ) {
                const int diff = abs(val - min);
                const int step = m_step.toInt( &res );
                res = res && ( 0 == ( diff % step ) );
                if ( not res ) {
                    return false;
                }
            }
        }
        break;
    case TypeEnum:
        res = value.canConvert( QVariant::Int );
        res = res && hasAvailableValues();
        if ( res ){
            const int val = value.toInt();
            foreach( const QVariant& available_value, m_available_values ) {
                const int available_value_int = available_value.toInt( & res );
                if ( not res ) {
                    return false;
                }
                if ( val == available_value_int ) {
                    return true;
                }
            }
            res = false;
        }
        break;
    case TypeUnsigned:
    case TypeCounter:
    case TypeGauge:
        res = value.canConvert( QVariant::UInt );
        if ( res && hasLimits() ) {
            const unsigned val = value.toUInt();
            const unsigned min = mininum().toUInt( &res );
            res = res && ( val >= min );
            if ( not res ) {
                return false;
            }

            const unsigned max = maximum().toUInt( &res );
            res = res && ( val <= max );
            if ( not res ) {
                return false;
            }

            if ( hasStep() ) {
                const unsigned diff = val - min;
                const unsigned step = m_step.toUInt( &res );
                res = res && ( 0 == ( diff % step ) );
                if ( not res ) {
                    return false;
                }
            }
        }
        break;
    case TypeReal:
        res = value.canConvert( QVariant::Double );
        if ( res && hasLimits() ) {
            const double val = value.toDouble();
            const double min = mininum().toDouble( &res );
            res = res && ( val >= min );
            if ( not res ) {
                return false;
            }

            const double max = maximum().toDouble( &res );
            res = res && ( val <= max );
            if ( not res ) {
                return false;
            }

            if ( hasStep() ) {
                const double step = m_step.toDouble( &res );
                if ( res ) {
                    const double double_coef = fabs(val - min) / step;
                    const int int_coef = static_cast< int >( double_coef );
                    const double diff = double_coef - int_coef;
                    const double maximum_diff = 0.0000000001;
                    res = diff < maximum_diff;
                }
            }
        }
        break;
    case TypeIpAddress:
        res = value.canConvert( QVariant::UInt );
        if ( res ) {
            const unsigned val = value.toUInt();
            const QString text = QHostAddress( val ).toString();
            const QRegExp ip_regex( "^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$" );
            res = ip_regex.exactMatch( text );
        }
        break;
    case TypeTimeTicks:
        res = value.canConvert( QVariant::UInt );
        break;
    case TypeString:
        res = value.canConvert( QVariant::String );
        break;
    default:
        qWarning() << Q_FUNC_INFO << "unsupported type(" << type() << ")";
        break;
    }
    return res;
}

void QtSnmpObjectDescription::setLimits( const QVariant& minimum, const QVariant& maximum ) {
    m_limits.first = minimum;
    m_limits.second = maximum;
    m_is_limits_was_set = true;
}

bool QtSnmpObjectDescription::hasLimits() const {
    return m_is_limits_was_set;
}

QVariant QtSnmpObjectDescription::mininum() const {
    return m_limits.first;
}

QVariant QtSnmpObjectDescription::maximum() const {
    return m_limits.second;
}

void QtSnmpObjectDescription::setStep( const QVariant& step ) {
    m_step = step;
    m_is_step_was_set = true;
}

bool QtSnmpObjectDescription::hasStep() const {
    return m_is_step_was_set;
}

QVariant QtSnmpObjectDescription::step() const {
    return m_step;
}

void QtSnmpObjectDescription::setAvailableValues( const QList< QVariant >& list ) {
    m_available_values = list;
    m_is_available_values_was_set = true;
}

bool QtSnmpObjectDescription::hasAvailableValues() const {
    return m_is_available_values_was_set;
}

QList< QVariant > QtSnmpObjectDescription::availableValues() const {
    return m_available_values;
}

void QtSnmpObjectDescription::setReadOnly( const bool value ) {
    m_is_read_only = value;
}

bool QtSnmpObjectDescription::isReadOnly() const {
    return m_is_read_only;
}

void QtSnmpObjectDescription::setWriteable( const bool value ) {
    setReadOnly( ! value );
}

bool QtSnmpObjectDescription::isWriteable() const {
    return ! isReadOnly();
}

QDebug operator<<( QDebug stream, const QtSnmpObjectDescription& obj ) {
    stream << "SnmpObjectDescription( ";
    stream << "oid:" << obj.oid() << "; ";
    stream << "type:" << obj.type() << "; ";
    if ( obj.hasLimits() ) {
        stream << "limit.min:" << obj.mininum() << "; ";
        stream << "limit.max:" << obj.maximum() << "; ";
    }
    if ( obj.hasStep() ) {
        stream << "step:" << obj.step() << "; ";
    }
    if ( obj.hasAvailableValues() ) {
        stream << "available values:" << obj.availableValues() << "; ";
    }
    stream << "is_writeable:" << obj.isWriteable() << ")";
    return stream;
}
