#pragma once

#include <QString>
#include <QVariant>
#include <QPair>
#include <QList>
#include <QDebug>
#include "win_export.h"

class WIN_EXPORT QtSnmpObjectDescription {
public:
    enum Type {
        TypeInterger,
        TypeEnum,
        TypeUnsigned,
        TypeReal,
        TypeIpAddress,
        TypeTimeTicks,
        TypeString,

        LimitOfTypes
    };

public:
    QtSnmpObjectDescription( const QString& oid, const Type );
    QtSnmpObjectDescription( const QtSnmpObjectDescription& ) = default;
    QtSnmpObjectDescription& operator=( const QtSnmpObjectDescription& ) = default;
    bool isValid() const;

    QString oid() const;

    Type type() const;

    bool checkValue( const QVariant& ) const;

    void setLimits( const QVariant& minimum, const QVariant& maximum );
    bool hasLimits() const;
    QVariant mininum() const;
    QVariant maximum() const;

    void setStep( const QVariant& );
    bool hasStep() const;
    QVariant step() const;

    void setAvailableValues( const QList< QVariant >& );
    bool hasAvailableValues() const;
    QList< QVariant > availableValues() const;

    void setReadOnly( const bool );
    bool isReadOnly() const;
    void setWriteable( const bool );
    bool isWriteable() const;

private:
    QString m_oid;
    Type m_type = LimitOfTypes;
    QPair< QVariant, QVariant > m_limits;
    bool m_is_limits_was_set = false;
    QVariant m_step;
    bool m_is_step_was_set = false;
    QVariantList m_available_values;
    bool m_is_available_values_was_set = false;
    bool m_is_read_only = false;
};

QDebug operator<<( QDebug, const QtSnmpObjectDescription& );
