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

#include <QCheckBox>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QLineEdit>
#include <QListView>
#include <QListWidget>
#include <QPushButton>
#include <QSplitter>
#include <QTableWidget>
#include <QTextEdit>
#include <QVBoxLayout>
#include <QWidget>

#include <qmdnsengine/mdns.h>
#include <qmdnsengine/service.h>

#include "mainwindow.h"
#include "servicemodel.h"

Q_DECLARE_METATYPE(QMdnsEngine::Service)

MainWindow::MainWindow()
    : _log(new QTextEdit(tr("Initializing application"))),
      _resolver(nullptr)
{
    setWindowTitle(tr("mDNS Browser"));
    resize(640, 480);

    _serviceType = new QLineEdit(tr("_shelly._tcp.local."));
    mStartStop = new QPushButton(tr("Browse"));
    mServices = new QListView;
    mAddresses = new QListWidget;
    mAttributes = new QTableWidget;
    mAttributes->setSelectionBehavior(QAbstractItemView::SelectRows);

    QVBoxLayout *rootLayout = new QVBoxLayout;
    QWidget *widget = new QWidget;
    widget->setLayout(rootLayout);
    setCentralWidget(widget);

    QCheckBox *any = new QCheckBox(tr("Any"));

    QHBoxLayout *typeLayout = new QHBoxLayout;
    typeLayout->addWidget(_serviceType, 1);
    typeLayout->addWidget(any);
    typeLayout->addWidget(mStartStop);
    rootLayout->addLayout(typeLayout);

    QSplitter *vSplitter = new QSplitter;
    vSplitter->setOrientation(Qt::Vertical);
    vSplitter->addWidget(mAddresses);
    vSplitter->addWidget(mAttributes);

    QSplitter *hSplitter = new QSplitter;
    hSplitter->addWidget(mServices);
    hSplitter->addWidget(vSplitter);

    QHBoxLayout *servicesLayout = new QHBoxLayout;
    servicesLayout->addWidget(hSplitter);
    rootLayout->addLayout(servicesLayout);
    // Add the log
    rootLayout->addWidget(_log, 1);

    connect(any, &QCheckBox::toggled, this, &MainWindow::onToggled);
    connect(mStartStop, &QPushButton::clicked, this, &MainWindow::onClicked);
}

void MainWindow::onToggled(bool checked)
{
    if (checked) {
        _serviceType->setText(QMdnsEngine::MdnsBrowseType);
    }
    _serviceType->setEnabled(!checked);
}

void MainWindow::onClicked()
{
    if (_serviceModel) {
        mServices->setModel(nullptr);
        delete _serviceModel;
        mAttributes->clear();
        mAttributes->setColumnCount(0);
    }

    _serviceModel = new ServiceModel(&_server, _serviceType->text().toUtf8());
    mServices->setModel(_serviceModel);

    connect(mServices->selectionModel(), &QItemSelectionModel::selectionChanged, this, &MainWindow::onSelectionChanged);
}

void MainWindow::onSelectionChanged(const QItemSelection &selected, const QItemSelection &)
{
    mAddresses->clear();
    mAttributes->clear();
    mAttributes->setColumnCount(0);

    if (_resolver) {
        delete _resolver;
        _resolver = nullptr;
    }

    if (selected.count()) {
        auto service = _serviceModel->data(selected.at(0).topLeft(), Qt::UserRole).value<QMdnsEngine::Service>();

        // Show TXT values
        auto attributes = service.attributes();
        mAttributes->setRowCount(attributes.keys().count());
        mAttributes->setColumnCount(2);
        mAttributes->setHorizontalHeaderLabels({tr("Key"), tr("Value")});
        mAttributes->horizontalHeader()->setStretchLastSection(true);
        mAttributes->verticalHeader()->setVisible(false);
        int row = 0;
        for (auto i = attributes.constBegin(); i != attributes.constEnd(); ++i, ++row) {
            mAttributes->setItem(row, 0, new QTableWidgetItem(QString(i.key())));
            mAttributes->setItem(row, 1, new QTableWidgetItem(QString(i.value())));
        }

        // Resolve the address
        _resolver = new QMdnsEngine::Resolver(&_server, service.hostname(), nullptr, this);
        connect(_resolver, &QMdnsEngine::Resolver::resolved, [this](const QHostAddress &address) {
            mAddresses->addItem(address.toString());
        });
    }
}
