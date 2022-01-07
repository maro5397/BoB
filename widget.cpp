#include "widget.h"
#include "ui_widget.h"

Widget::Widget(QWidget *parent)
    : QWidget(parent)
    , ui(new Ui::Widget)
{
    ui->setupUi(this);
    setControl();
}

Widget::~Widget()
{
    delete ui;
}

void Widget::changeMoney(int coin)
{
    money += coin;
    ui->lcdNumber->display(money);
    setControl();
}

void Widget::setControl()
{
    ui->pbCoffee->setEnabled(money >= 200);
    ui->pbMilk->setEnabled(money >= 100);
    ui->pbTea->setEnabled(money >= 150);
}


void Widget::on_pbCoin500_clicked()
{
    changeMoney(500);
}


void Widget::on_pbCoin100_clicked()
{
    changeMoney(100);
}


void Widget::on_pbCoin50_clicked()
{
    changeMoney(50);
}


void Widget::on_pbCoin10_clicked()
{
    changeMoney(10);
}


void Widget::on_pbCoffee_clicked()
{
    changeMoney(-200);
}


void Widget::on_pbTea_clicked()
{
    changeMoney(-150);
}


void Widget::on_pbMilk_clicked()
{
    changeMoney(-100);
}


void Widget::on_pbReset_clicked()
{
    QString msg = "==========return money==========\n";
    msg += "order of 500: "+QString::number(money/500)+"\n";
    money %= 500;
    msg += "order of 100: "+QString::number(money/100)+"\n";
    money %= 100;
    msg += "order of 50: "+QString::number(money/50)+"\n";
    money %= 50;
    msg += "order of 10: "+QString::number(money/10)+"\n";
    money %= 10;
    QMessageBox::information(nullptr, "Reset", msg);
    money = 0;
    ui->lcdNumber->display(money);
    setControl();
}

