/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2017 Nathan Osman
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

#include "servicemodel.h"

Q_DECLARE_METATYPE(QMdnsEngine::Service)

ServiceModel::ServiceModel(QMdnsEngine::Server *server, const QByteArray &type)
    : _browser(server, type, &_cache)
{
    _browser.on<QMdnsEngine::ServiceAdded>([this](const QMdnsEngine::ServiceAdded& event, const QMdnsEngine::Browser&) {
        onServiceAdded(event.service);
    });
    _browser.on<QMdnsEngine::ServiceUpdated>([this](const QMdnsEngine::ServiceUpdated& event, const QMdnsEngine::Browser&) {
        onServiceUpdated(event.service);
    });
    _browser.on<QMdnsEngine::ServiceRemoved>([this](const QMdnsEngine::ServiceRemoved& event, const QMdnsEngine::Browser&) {
        onServiceRemoved(event.service);
    });
}

int ServiceModel::rowCount(const QModelIndex &) const
{
    return _services.count();
}

QVariant ServiceModel::data(const QModelIndex &index, int role) const
{
    // Ensure the index points to a valid row
    if (!index.isValid() || index.row() < 0 || index.row() >= _services.count()) {
        return QVariant();
    }

    QMdnsEngine::Service service = _services.at(index.row());

    switch (role) {
    case Qt::DisplayRole:
        return QString("%1 (%2)")
            .arg(QString(service.name()))
            .arg(QString(service.type()));
    case Qt::UserRole:
        return QVariant::fromValue(service);
    }

    return QVariant();
}

void ServiceModel::onServiceAdded(const QMdnsEngine::Service &service)
{
    beginInsertRows(QModelIndex(), _services.count(), _services.count());
    _services.append(service);
    endInsertRows();
}

void ServiceModel::onServiceUpdated(const QMdnsEngine::Service &service)
{
    int i = findService(service.name());
    if (i != -1) {
        _services.replace(i, service);
        emit dataChanged(index(i), index(i));
    }
}

void ServiceModel::onServiceRemoved(const QMdnsEngine::Service &service)
{
    int i = findService(service.name());
    if (i != -1) {
        beginRemoveRows(QModelIndex(), i, i);
        _services.removeAt(i);
        endRemoveRows();
    }
}

int ServiceModel::findService(const QByteArray &name)
{
    for (auto i = _services.constBegin(); i != _services.constEnd(); ++i) {
        if ((*i).name() == name) {
            return i - _services.constBegin();
        }
    }
    return -1;
}
