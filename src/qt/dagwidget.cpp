// Copyright (c) 2015-2025 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "dagwidget.h"
#include "chain.h"
#include "random.h"
#include "unlimited.h"
#include "utiltime.h"
#include "validation/tailstorm.h"

#include <QApplication>
#include <QGraphicsItem>
#include <QGraphicsPathItem>
#include <QGraphicsProxyWidget>
#include <QGraphicsView>
#include <QLabel>
#include <QPainterPath>
#include <QPushButton>
#include <QResizeEvent>
#include <QScrollBar>
#include <QSignalMapper>

extern std::atomic<bool> fRescan;
extern std::atomic<bool> fReindex;

BlockDescDialog::BlockDescDialog(QString *desc, QWidget *parent, DagWidget *dagwidget) : ui(new Ui::BlockDescDialog)
{
    ui->setupUi(this);
    ui->detailText->setHtml(*desc);

    _dagwidget = dagwidget;
}

BlockDescDialog::~BlockDescDialog() { delete ui; }

void BlockDescDialog::hideEvent(QHideEvent *event)
{
    if (!ui)
        return;
    if (_dagwidget)
    {
        LOCK(_dagwidget->cs_info);
        _dagwidget->RemoveHighlight();
        _dagwidget->uiBlockDesc = nullptr;
        _dagwidget->ShowPauseButton();
    }
}


DagWidget::DagWidget(QWidget *parent) : QWidget(parent)
{
    // Which simulation to run (1, 2, 3, 4 or 5).
    // Simulation 3 and 4 use the data from the setup of simulation 2.
    // If Zero is chosen then the simulation won't run and we'll pick up the actual blocks being mined instead.
    nRunSimulation = 0;
    SetupSimulation1();
    SetupSimulation2();
    SetupSimulation5();

    _parent = parent;

    scene = new QGraphicsScene();
    scene->setItemIndexMethod(QGraphicsScene::ItemIndexMethod::NoIndex);
    scene->setBackgroundBrush(QColor(245, 245, 245));

    view = new QGraphicsView(scene, this);
    view->setViewportUpdateMode(QGraphicsView::FullViewportUpdate);
    view->setTransformationAnchor(QGraphicsView::AnchorUnderMouse);

    greenBrush = QBrush(QColor(143, 188, 143)); // qt6 - QColorConstants::Svg::darkseagreen
    greyBrush = QBrush(QColor(220, 220, 220)); // qt6 - QColorConstants::Svg::gainsboro
    redBrush = QBrush(QColor(250, 128, 114)); // qt6 - QColorConstants::Svg::salmon
    // blueBrush = QBrush(QColor(176, 196, 222)); // qt6 - QColorConstants::Svg::lightsteelblue
    blueBrush = QBrush(QColor(143, 188, 143)); // qt6 - QColorConstants::Svg::darkseagreen
    goldBrush = QBrush(QColor(218, 165, 32)); // qt6 - QColorConstants::Svg::goldenrod
    violetBrush = QBrush(QColor(216, 191, 216)); // qt6 - QColorConstants::Svg::thistle
    whiteBrush = QBrush(QColor(255, 255, 255));
    blackBrush = QBrush(QColor(0, 0, 0));
    charcoalBrush = QBrush(QColor(78, 78, 78));
    steelBlueBrush = QBrush(QColor(70, 130, 180));

    borderPen.setWidth(1);
    borderPen.setColor(QColor(78, 78, 78));
    thickBorderPen.setWidth(2);
    thickBorderPen.setColor(QColor(78, 78, 78));
    widgetBorderPen.setWidth(1);
    widgetBorderPen.setColor(QColor(200, 200, 200));
    dashedLinePen.setStyle(Qt::DashLine);
    dashedLinePen.setWidth(1);
    dashedLinePen.setColor(QColor(95, 158, 160)); // qt6 - QColorConstants::Svg::cadetblue

    size_t parentWidth = _parent->width();
    size_t parentHeight = _parent->height();
    view->resize(parentWidth - 47, parentHeight - 75);
    view->show();

    connect(view->horizontalScrollBar(), SIGNAL(sliderPressed()), this, SLOT(sliderPress()));

    if (nRunSimulation > 0)
    {
        pollTimer = new QTimer(this);
        connect(pollTimer, SIGNAL(timeout()), this, SLOT(dagSimulation()));
        pollTimer->start(4200 / 2);

        pollTimer2 = new QTimer(this);
        connect(pollTimer2, SIGNAL(timeout()), this, SLOT(dagSimulation()));
        pollTimer2->start(2500 / 2);
    }
    else
    {
        SubscribeToCoreSignals();
    }
}

DagWidget::~DagWidget()
{
    UnsubscribeFromCoreSignals();

    LOCK(cs_info);
    mapDag.clear();
    mapInfo.clear();
    mapInfoByMiningHash.clear();
    mapDeferredInfo.clear();
    delete uiBlockDesc;

    if (scene)
        scene->clear();
    view->setScene(0); // must remove scene from view first
    delete view;
    delete scene;
}

void DagWidget::resizeGraphicsView(QWidget *console)
{
    // resizing of the CGraphicsView is not straightforward, hence the need for this function.
    LOCK(cs_info);
    if (console && _parent && view)
    {
        bool fIsSliderMax = (view->horizontalScrollBar()->sliderPosition() == view->horizontalScrollBar()->maximum());
        size_t consoleWidth = console->width();
        size_t consoleHeight = console->height();

        // size the graphics area
        _parent->resize(consoleWidth - 28, consoleHeight - 69);
        view->resize(consoleWidth - 46, consoleHeight - 104);

        // Set slider position if needed.
        if (fIsSliderMax)
        {
            view->horizontalScrollBar()->setSliderPosition(view->horizontalScrollBar()->maximum());
        }
    }
}

void DagWidget::mousePressEvent(QMouseEvent *event)
{
    if (event->button() == Qt::LeftButton)
    {
        QString infoString;
        {
            LOCK(cs_info);
            if (!scene || !view)
                return;

            // Find the correct item.  We want the block item, not the text item which
            // if present will be the top item.
            QList<QGraphicsItem *> items = view->items(event->pos());
            if (!items.empty())
            {
                for (QGraphicsItem *item : items)
                {
                    for (auto &i : mapInfo)
                    {
                        auto info = i.second;
                        if ((info->item != nullptr) && (info->item == item))
                        {
                            // Block
                            if (info->blockType == STORM_BLOCK)
                            {
                                infoString.append("<b> " + tr("Subblock: ") + "</b>  " +
                                                  QString::fromStdString(info->blockhash.ToString()) + "<br>");
                            }
                            else
                            {
                                if (info->blockType == LEGACY_BLOCK)
                                {
                                    infoString.append("<b> " + tr("Block: ") + "</b>  " +
                                                      QString::fromStdString(info->blockhash.ToString()) + "<br>");
                                }
                                else
                                {
                                    infoString.append("<b> " + tr("Summary Block: ") + "</b>  " +
                                                      QString::fromStdString(info->blockhash.ToString()) + "<br>");
                                }
                            }

                            // Previous Block
                            if (info->vBlockPointsTo.empty())
                            {
                                infoString.append("<b> " + tr("Previous block: ") + "</b>  N/A <br>");
                            }
                            else if (info->blockType == STORM_BLOCK)
                            {
                                if (info->nDagHeight == 1)
                                {
                                    infoString.append(
                                        "<b> " + tr("Previous Summary Block: ") + "</b>  " +
                                        QString::fromStdString(info->vBlockPointsTo[0].prevBlock.ToString()) + "<br>");
                                }
                                else
                                {
                                    for (auto &link : info->vBlockPointsTo)
                                    {
                                        infoString.append("<b> " + tr("Previous Subblock: ") + "</b>  " +
                                                          QString::fromStdString(link.prevBlock.ToString()) + "<br>");
                                    }
                                }
                            }
                            else if (info->blockType == SUMMARY)
                            {
                                for (auto &link : info->vBlockPointsTo)
                                {
                                    infoString.append("<b> " + tr("Previous Subblock: ") + "</b>  " +
                                                      QString::fromStdString(link.prevBlock.ToString()) + "<br>");
                                }
                            }
                            else
                            {
                                infoString.append("<b> " + tr("Previous Block: ") + "</b>  " +
                                                  QString::fromStdString(info->vBlockPointsTo[0].prevBlock.ToString()) +
                                                  "<br>");
                            }

                            // Block height
                            if (info->blockType == STORM_BLOCK)
                            {
                                infoString.append("<b> " + tr("For block height: ") + "</b>  " +
                                                  QString::number(info->nBlockHeight) + "<br>");
                            }
                            else
                            {
                                infoString.append("<b> " + tr("Block Height: ") + "</b>  " +
                                                  QString::number(info->nBlockHeight) + "<br>");
                            }

                            // Dag Height
                            if (info->blockType == STORM_BLOCK)
                            {
                                infoString.append("<b> " + tr("Dag Height: ") + "</b>  " +
                                                  QString::number(info->nDagHeight) + "<br>");
                            }

                            // Block Sequence Id
                            if (info->blockType == STORM_BLOCK && info->nSequenceId > 0)
                            {
                                infoString.append("<b> " + tr("Sequence Id: ") + "</b>  " +
                                                  QString::number(info->nSequenceId) + "<br>");
                            }

                            // Number of Transactions in block
                            infoString.append("<b> " + tr("Transactions: ") + "</b>  " +
                                              QString::number(info->nTransactions) + "<br>");

                            // Block Size.
                            infoString.append("<b> " + tr("Block Size (bytes): ") + "</b>  " +
                                              QString::number(info->nBlockSize) + "<br>");

                            // If we clicked on the same item which had already been opened then
                            // don't redraw it.
                            if (pSelected == i.second)
                            {
                                RemoveHighlight();
                                if (uiBlockDesc)
                                {
                                    delete uiBlockDesc;
                                    uiBlockDesc = nullptr;
                                }
                                ShowPauseButton();
                                return;
                            }
                            else
                            {
                                // Remove old highlight before adding the new one.
                                RemoveHighlight();
                            }

                            // Add a highlight border around the selected block
                            qreal offset = 8;
                            qreal yshift = 4;
                            if (info->blockType == STORM_BLOCK)
                            {
                                offset = 5;
                                yshift = 7;
                            }
                            QPainterPath path;
                            QRectF rect(info->x - offset, info->y + yshift - info->itemHeight / 2,
                                info->itemWidth + (offset * 2), info->itemHeight + (offset * 2));
                            path.addRoundedRect(rect, radius, radius - 1);
                            itemHighlight = scene->addPath(path, thickBorderPen, QBrush());
                            pSelected = i.second;
                            if (pSelected)
                            {
                                view->centerOn(pSelected->item);
                                ShowContinueButton();
                            }
                            break;
                        }
                    }
                }
            }
        }

        // display the information string.
        if (!infoString.isEmpty())
        {
            if (uiBlockDesc)
            {
                uiBlockDesc->ui->detailText->setHtml(infoString);
            }
            else
            {
                uiBlockDesc = new BlockDescDialog(&infoString, this, this);
                uiBlockDesc->setWindowTitle("Block Details");
                int nWidth = 310;
                int nHeight = 350;
                uiBlockDesc->setFixedSize(nWidth, nHeight);
                QPointF globalPos = this->mapToGlobal(this->pos());
                qreal x = globalPos.x();
                if (globalPos.x() - nWidth - 24 > 0)
                    x = globalPos.x() - nWidth - 24;
                qreal y = globalPos.y();
                uiBlockDesc->move(x, y);
                uiBlockDesc->show();
            }
        }

        if (uiBlockDesc)
            uiBlockDesc->raise();

        return;
    }
}

void DagWidget::hideEvent(QHideEvent *event)
{
    LOCK(cs_info);
    if (!uiBlockDesc)
        return;

    delete uiBlockDesc;
    uiBlockDesc = nullptr;

    RemoveHighlight();
    ShowPauseButton();
}

void DagWidget::sliderPress() { ShowContinueButton(); }

void DagWidget::DeferItem(uint256 hash,
    uint256 mininghash,
    uint256 prevhash,
    uint32_t nDagHeight,
    uint32_t nSequenceId,
    uint32_t nBlockHeight,
    uint64_t nTransactions,
    uint64_t nBlockSize,
    std::vector<Link> &_vpointsto,
    bool fDoubleSpend,
    uint32_t nFork,
    uint8_t blockType,
    bool fHeader,
    const CBlockHeader &header)
{
    LOCK(cs_info);

    // Just add placeholders for now. The actuall coordinates and size will be calculated
    // when the item gets added to the viewer.
    qreal x = 0;
    qreal y = 0;
    qreal itemWidth = 0;
    qreal itemHeight = 0;

    ItemInfo temp{hash, mininghash, 0, nDagHeight, nSequenceId, nBlockHeight, nTransactions, nBlockSize, nFork, x, y,
        itemWidth, itemHeight, _vpointsto, true, fDoubleSpend, blockType, !fHeader, header, nullptr, nullptr, nullptr,
        nullptr, nullptr};
    std::shared_ptr<ItemInfo> info = std::make_shared<ItemInfo>(temp);

    if (!mapDeferredInfo.count(hash))
    {
        mapDeferredInfo.emplace(hash, info);
    }
    LOG(DAG, "Dagwidget: deferred map size %ld\n", mapDeferredInfo.size());
}

void DagWidget::AddItem(uint256 hash,
    uint256 mininghash,
    uint256 prevhash,
    uint32_t nDagHeight,
    uint32_t nSequenceId,
    uint32_t nBlockHeight,
    uint64_t nTransactions,
    uint64_t nBlockSize,
    std::vector<Link> _vpointsto,
    bool fDoubleSpend,
    uint32_t nFork,
    uint8_t blockType,
    bool fHeader,
    const CBlockHeader &header)
{
    LOCK(cs_info);
    if (!view || !scene)
        return;

    // Don't start the blockviewer until the chain is almost synced.
    if (!fStartBlockViewer)
    {
        if (IsChainSyncd() && !fReindex && !fRescan)
        {
            fStartBlockViewer = true;
        }
        else
        {
            return;
        }
    }

    // Trim the maps if we've hit our limit
    while (mapDag.size() >= DEFAULT_MAX_BLOCKS)
    {
        // Trim items in decending stacking order. These items are no longer in the viewport
        // and so should not trigger a re-paint.
        for (auto &it : mapDag.begin()->second)
        {
            if (fQLabelsEnabled)
            {
                if (it->itemText1)
                {
                    scene->removeItem(it->itemText1);
                    delete it->itemText1;
                    it->itemText1 = nullptr;
                }
                if (it->itemText2)
                {
                    scene->removeItem(it->itemText2);
                    delete it->itemText2;
                    it->itemText2 = nullptr;
                }
            }
            else
            {
                if (it->itemText)
                {
                    scene->removeItem(it->itemText);
                    delete it->itemText;
                    it->itemText = nullptr;
                }
            }

            if (it->item)
            {
                scene->removeItem(it->item);
                delete it->item;
                it->item = nullptr;
            }

            if (it->litem)
            {
                scene->removeItem(it->litem);
                delete it->litem;
                it->litem = nullptr;
            }

            // now trim the block from the map
            mapInfo.erase(it->blockhash);
            mapInfoByMiningHash.erase(it->mininghash);
        }
        mapDag.erase(mapDag.begin());
    }

    // If the block height is less than the smallest block height we currently have in our
    // dag then do not accept it since we've already trimmed passed that height already.
    uint32_t nDagViewerHeight = GetNextDagViewerHeight(prevhash, header);

    if ((mapDag.begin() != mapDag.end()) && (nDagViewerHeight < mapDag.begin()->first))
        return;
    // If we have the item already and we try to add it as a header again then do nothing
    if (mapInfo.count(hash) && fHeader == true)
        return;
    // If we have it already and it's a block then return
    if (mapInfo.count(hash) && mapInfo[hash]->fHaveBlock)
        return;

    // Set prevhash to null if there is no prevhash in the dag already.
    if (!mapInfo.count(prevhash))
    {
        prevhash.SetNull();
        _vpointsto.clear();
    }
    // Determine if this is a new block to display or whether we already displayed it
    // as a header
    bool fIsNewBlockToDisplay = true;
    if (mapInfo.count(hash))
    {
        fIsNewBlockToDisplay = false;
    }

    // setup item info and tracking map for this block
    qreal x = 0;
    qreal y = 0;
    qreal itemWidth = subblockWidth;
    qreal itemHeight = subblockHeight;
    if (blockType == SUMMARY)
    {
        itemWidth = summaryWidth;
        itemHeight = summaryHeight;
    }
    else if (blockType == LEGACY_BLOCK)
    {
        itemWidth = legacyWidth;
        itemHeight = legacyHeight;
    }

    // If this is not the first item then get the previous 'x' value and add the next
    // additional amount we'll need.
    uint32_t nCheckHeight = nDagViewerHeight - 1;
    if (mapDag.count(nCheckHeight) > 0)
    {
        // If this is the first item in a new chain but a prior chain already exists
        // and this first item height is larger than the beginning of the first chain
        // then set the x value correctly.
        // This is an edge case where we the node just started up and received a load
        // of headers from some competing but older chain and but then we receive a block
        // on the main chain which is from a higher hight than the first header we received.
        x = mapDag[nCheckHeight][0]->x + mapDag[nCheckHeight][0]->itemWidth + distance;
    }

    // Create the new block item.
    ItemInfo temp{hash, mininghash, nDagViewerHeight, nDagHeight, nSequenceId, nBlockHeight, nTransactions, nBlockSize,
        nFork, x, y, itemWidth, itemHeight, _vpointsto, true, fDoubleSpend, blockType, !fHeader, header, nullptr,
        nullptr, nullptr, nullptr, nullptr};
    std::shared_ptr<ItemInfo> info = std::make_shared<ItemInfo>(temp);

    if (blockType == SUMMARY)
    {
        nLastSummaryDagViewerHeight = nDagViewerHeight;
    }

    // Add the item to the tracking maps or update it if it exists already.
    // Also need to update the block sequence id here since we don't know for sure what it will
    // be until we get a full block.
    if (!mapInfo.count(hash))
    {
        mapInfo.emplace(hash, info);
        mapInfoByMiningHash.emplace(mininghash, info);
        mapDag[nDagViewerHeight].push_back(info);

        if (!fHeader)
        {
            mapInfo[hash]->fHaveBlock = true;
        }
    }
    else if (mapInfo.count(hash) && !mapInfo[hash]->fHaveBlock && !fHeader)
    {
        mapInfo[hash]->fHaveBlock = true;
    }
    else
    {
        return;
    }

    // Add block to the graphics view
    {
        // Create the block info object and modify and update the "y" value according to how many
        // blocks exist at the same block height.
        const std::vector<std::shared_ptr<ItemInfo> > &vDag = mapDag[nDagViewerHeight];
        qreal offset = 0;
        if (blockType == SUMMARY)
        {
            offset = (distance / 2) + itemHeight;
        }
        else if (blockType == STORM_BLOCK)
        {
            offset = distance + (itemHeight / 2);

            // Handle special case where a Summary Block had arrived and been
            // drawn on screen first before a subblock orphan. In this case
            // we need to make a small adjustment to re-position the subblock.
            for (auto &item : vDag)
            {
                if (IsSummaryBlock(item->header))
                {
                    offset = distance + (summaryHeight / 2);
                    break;
                }
            }
        }
        else
        {
            offset = distance + itemHeight;
        }

        // Once we get two items then pick a random side of chain to place the first dag item
        if (fIsNewBlockToDisplay)
        {
            // find the max y and min y values
            qreal max_y = 0;
            qreal min_y = 0;
            bool yZero = false;
            for (auto it : vDag)
            {
                if (it->y > max_y)
                    max_y = it->y;
                if (it->y < min_y)
                    min_y = it->y;

                // Check if x-axis, y=0 (baseline) slot is already filled with an item
                if (it->y == 0 && it->item)
                    yZero = true;
            }

            // Find the max y and min y for the prev block that the new block points to.
            qreal max_prev_y = 0;
            qreal min_prev_y = 0;
            for (Link link : info->vBlockPointsTo)
            {
                if (!link.fHardLink)
                    continue;

                // get the max y for blocks we're pointing to.
                if (mapInfo.count(link.prevBlock) == 0)
                {
                    LOG(DAG, "Dagwidget: Did not find prevous link on the screen %s", link.prevBlock.ToString());
                    continue;
                }

                qreal prev_y = mapInfo[link.prevBlock]->y;
                if (prev_y > max_prev_y)
                    max_prev_y = prev_y;
                if (prev_y < min_prev_y)
                    min_prev_y = prev_y;
            }

            // If the previous blocks y value was zero then cycle from one side to the other
            if (max_prev_y == 0 && min_prev_y == 0)
            {
                if (vDag.size() == 2)
                {
                    if (vDag.size() % 2 == 0)
                    {
                        y += offset;
                    }
                    else
                    {
                        y -= offset;
                    }
                }
                if (vDag.size() >= 3)
                {
                    if (abs(min_y) < abs(max_y))
                        y = min_y - offset;
                    if (abs(min_y) > abs(max_y))
                        y = max_y + offset;
                    if (abs(min_y) == abs(max_y))
                    {
                        if (vDag.size() % 2 == 0)
                        {
                            y = max_y + offset;
                        }
                        else
                        {
                            y = min_y - offset;
                        }
                    }
                }
            }
            // Otherwise we want to keep the new blocks y-axis position on the same side of the x-axis.
            // This wasy we don't need to cross over any lines when the new blocks connecting line is drawn.
            else
            {
                if (max_prev_y > 0)
                {
                    y = max_y + offset;
                }
                else
                {
                    y = min_y - offset;
                }

                if (!yZero && max_y == 0 && min_y == 0)
                    y = 0;
            }

            info->y = y;
        }
        else
        {
            y = mapInfo[hash]->y;
        }

        // Add the new block and connecting lines to the scene.
        if (blockType == STORM_BLOCK)
        {
            // Add the connecting lines
            for (Link link : info->vBlockPointsTo)
            {
                // get the max y for blocks we're pointing to.
                if (mapInfo.count(link.prevBlock) == 0)
                {
                    LOG(DAG, "Dagwidget: Did not find prevous link on the screen %s", link.prevBlock.ToString());
                    continue;
                }

                // Add the lines from the center of one block to the center of the preceding block or blocks.
                QPen pen;
                if (link.fHardLink)
                {
                    pen = borderPen;
                }
                else
                {
                    // Swap these two lines of code if you want to see soft links.
                    // pen = dashedLinePen;
                    continue;
                }

                if (!mapInfo[hash]->item)
                {
                    // create line with a zvalue less than the prev block. This way the line portions that
                    // are withing the block rectangle won't be seen.
                    QGraphicsLineItem *litem = new QGraphicsLineItem();
                    litem->setLine(mapInfo[link.prevBlock]->x + (mapInfo[link.prevBlock]->itemWidth / 2),
                        mapInfo[link.prevBlock]->y + (itemHeight / 2), x + (itemWidth / 2), y + (itemHeight / 2));
                    litem->setPen(pen);
                    litem->setZValue(-1);
                    scene->addItem(litem);
                    mapInfo[hash]->litem = litem;
                }

                // Update the color of the preceding block.
                QBrush prevBrush;
                QPen prevPen = borderPen;
                if (!mapInfo[link.prevBlock]->fHaveBlock)
                {
                    prevBrush = whiteBrush;
                    prevPen = dashedLinePen;
                }
                else if (mapInfo[link.prevBlock]->blockType == SUMMARY)
                {
                    prevBrush = blueBrush;
                }
                else if (blockType == STORM_BLOCK && mapInfo[link.prevBlock]->fHasDoubleSpend)
                {
                    prevBrush = redBrush;
                }
                else if (mapInfo[link.prevBlock]->blockType == STORM_BLOCK)
                {
                    prevBrush = violetBrush;
                }
                else if (mapInfo[link.prevBlock]->blockType == LEGACY_BLOCK)
                {
                    prevBrush = greenBrush;
                }
                else
                {
                    prevBrush = greenBrush;
                }

                if (mapInfo[link.prevBlock]->item)
                {
                    mapInfo[link.prevBlock]->item->setPen(prevPen);
                    mapInfo[link.prevBlock]->item->setBrush(prevBrush);
                    mapInfo[link.prevBlock]->item->update();
                }
            }

            // Add the new block
            QBrush brush;
            QPen pen = borderPen;
            if (fHeader)
            {
                brush = whiteBrush;
                pen = dashedLinePen;
            }
            else if (fDoubleSpend)
            {
                brush = redBrush;
            }
            else
            {
                brush = greyBrush;
            }

            if (mapInfo[hash]->item)
            {
                mapInfo[hash]->item->setPen(pen);
                mapInfo[hash]->item->setBrush(brush);
                mapInfo[hash]->item->update();
            }
            else
            {
                QPainterPath path;
                QRectF rect(x, y, itemWidth, itemHeight);
                path.addRoundedRect(rect, radius, radius - 1);

                QGraphicsPathItem *item = scene->addPath(path, pen, brush);
                mapInfo[hash]->item = item;
            }
        }
        else if (blockType == SUMMARY)
        {
            // Add the connecting lines
            for (Link link : info->vBlockPointsTo)
            {
                // get the max y for blocks we're pointing to.
                if (mapInfo.count(link.prevBlock) == 0)
                {
                    LOG(DAG, "Dagwidget: Did not find prevous link on the screen %s", link.prevBlock.ToString());
                    continue;
                }

                // Add the lines from the center of one block to the center of the preceding block or blocks.
                QPen pen;
                if (link.fHardLink)
                {
                    pen = borderPen;
                }
                else
                {
                    // Swap these two lines of code if you want to see soft links.
                    // pen = dashedLinePen;
                    continue;
                }

                if (!mapInfo[hash]->item)
                {
                    // create line with a zvalue less than the prev block. This way the line portions that
                    // are withing the block rectangle won't be seen.
                    QGraphicsLineItem *litem = new QGraphicsLineItem();
                    litem->setLine(mapInfo[link.prevBlock]->x + (mapInfo[link.prevBlock]->itemWidth / 2),
                        mapInfo[link.prevBlock]->y + (subblockHeight / 2), x + (mapInfo[link.prevBlock]->itemWidth / 2),
                        y + (subblockHeight / 2));
                    litem->setPen(pen);
                    litem->setZValue(-1);
                    scene->addItem(litem);
                    mapInfo[hash]->litem = litem;
                }

                // Update the color of the preceding block.
                QBrush prevBrush;
                QPen prevPen = borderPen;
                if (!mapInfo[link.prevBlock]->fHaveBlock)
                {
                    prevBrush = whiteBrush;
                    prevPen = dashedLinePen;
                }
                else if (mapInfo[link.prevBlock]->blockType == SUMMARY)
                {
                    prevBrush = blueBrush;
                }
                else if (mapInfo[link.prevBlock]->blockType == STORM_BLOCK)
                {
                    prevBrush = violetBrush;
                }
                else if (mapInfo[link.prevBlock]->blockType == LEGACY_BLOCK)
                {
                    prevBrush = greenBrush;
                }

                if (mapInfo[link.prevBlock]->item)
                {
                    mapInfo[link.prevBlock]->item->setPen(prevPen);
                    mapInfo[link.prevBlock]->item->setBrush(prevBrush);
                    mapInfo[link.prevBlock]->item->update();

                    if (fQLabelsEnabled && mapInfo[link.prevBlock]->itemText1 && mapInfo[link.prevBlock]->itemText2)
                    {
                        mapInfo[link.prevBlock]->itemText1->update();
                        mapInfo[link.prevBlock]->itemText2->update();
                    }
                }
            }

            QBrush brush;
            QPen pen = borderPen;
            if (fHeader)
            {
                brush = whiteBrush;
                pen = dashedLinePen;
            }
            else
            {
                brush = blueBrush;
            }


            if (mapInfo[hash]->item)
            {
                mapInfo[hash]->item->setPen(pen);
                mapInfo[hash]->item->setBrush(brush);
                mapInfo[hash]->item->update();
                if (fQLabelsEnabled && mapInfo[hash]->itemText1 && mapInfo[hash]->itemText2)
                {
                    mapInfo[hash]->itemText1->update();
                    mapInfo[hash]->itemText2->update();
                }
            }
            else
            {
                QPainterPath path;
                QRectF rect(x, y - (summaryHeight / 2) + (subblockHeight / 2), summaryWidth, summaryHeight);
                path.addRoundedRect(rect, radius, radius - 1);

                QGraphicsPathItem *item = scene->addPath(path, pen, brush);
                mapInfo[hash]->item = item;
                AddText(hash, pen, x, y, blockType);
            }
        }
        else // draw the legacy block
        {
            // Add the connecting lines
            for (Link link : info->vBlockPointsTo)
            {
                // get the max y for blocks we're pointing to.
                if (mapInfo.count(link.prevBlock) == 0)
                {
                    LOG(DAG, "Dagwidget: Did not find prevous link on the screen %s", link.prevBlock.ToString());
                    continue;
                }

                // Add the lines from the center of one block to the center of the preceding block or blocks.
                QPen pen;
                if (link.fHardLink)
                {
                    pen = borderPen;
                }
                else
                {
                    // Swap these two lines of code if you want to see soft links.
                    // pen = dashedLinePen;
                    continue;
                }
                if (!mapInfo.count(link.prevBlock))
                    continue;

                if (!mapInfo[hash]->item)
                {
                    // create line with a zvalue less than the prev block. This way the line portions that
                    // are withing the block rectangle won't be seen.
                    QGraphicsLineItem *litem = new QGraphicsLineItem();
                    litem->setLine(mapInfo[link.prevBlock]->x + (mapInfo[link.prevBlock]->itemWidth / 2),
                        mapInfo[link.prevBlock]->y + (subblockHeight / 2), x + (mapInfo[link.prevBlock]->itemWidth / 2),
                        y + (subblockHeight / 2));
                    litem->setPen(pen);
                    litem->setZValue(-1);
                    scene->addItem(litem);
                    mapInfo[hash]->litem = litem;
                }

                // Update the color of the preceding block.
                QBrush prevBrush;
                QPen prevPen = borderPen;
                if (!mapInfo[link.prevBlock]->fHaveBlock)
                {
                    prevBrush = whiteBrush;
                    prevPen = dashedLinePen;
                }
                else if (mapInfo[link.prevBlock]->fHasDoubleSpend)
                {
                    prevBrush = redBrush;
                }
                else
                {
                    prevBrush = greenBrush;
                }

                if (mapInfo[link.prevBlock]->item)
                {
                    mapInfo[link.prevBlock]->item->setPen(prevPen);
                    mapInfo[link.prevBlock]->item->setBrush(prevBrush);
                    mapInfo[link.prevBlock]->item->update();

                    if (fQLabelsEnabled && mapInfo[link.prevBlock]->itemText1 && mapInfo[link.prevBlock]->itemText2)
                    {
                        mapInfo[link.prevBlock]->itemText1->update();
                        mapInfo[link.prevBlock]->itemText2->update();
                    }
                }
            }

            QBrush brush;
            QPen pen = borderPen;
            if (fHeader)
            {
                brush = whiteBrush;
                pen = dashedLinePen;
            }
            else if (fDoubleSpend)
            {
                brush = redBrush;
            }
            else
            {
                brush = greyBrush;
            }

            if (mapInfo[hash]->item)
            {
                mapInfo[hash]->item->setPen(pen);
                mapInfo[hash]->item->setBrush(brush);
                mapInfo[hash]->item->update();
                if (fQLabelsEnabled && mapInfo[hash]->itemText1 && mapInfo[hash]->itemText2)
                {
                    mapInfo[hash]->itemText1->update();
                    mapInfo[hash]->itemText2->update();
                }
            }
            else
            {
                QPainterPath path;
                QRectF rect(x, y - (legacyHeight / 2) + (subblockHeight / 2), legacyWidth, legacyHeight);
                path.addRoundedRect(rect, radius, radius - 1);

                QGraphicsPathItem *item = scene->addPath(path, pen, brush);
                mapInfo[hash]->item = item;
                AddText(hash, pen, x, y, blockType);
            }
        }
    }

    // For a better visual, make the view just a little bigger than we need and
    // center the items so that the last item shows up near the right edge of
    // the view.
    qreal xCenterView = x - xOffset; // where to center the view
    qreal xEndView = x + xOffset; // the right edge of the view
    qreal xStartView = xEndView - DEFAULT_WIDTH_OF_VIEW; // the left edge of the view

    // Center the view on the item with the greatest x-coord if no other items are
    // selected.
    QPointF pEnd = view->mapToScene(QPoint(xEndView, 0));
    if (xCenterView >= xCenter || mapInfo.size() <= 2)
    {
        xCenter = xCenterView;
        if (IsChainSyncd())
        {
            view->setSceneRect(xStartView, 0 - pEnd.y(), DEFAULT_WIDTH_OF_VIEW, pEnd.y() * 2);
            if (!pSelected && !fPause)
            {
                view->centerOn(xCenter, 0);
                view->horizontalScrollBar()->setSliderPosition(view->horizontalScrollBar()->maximum());
            }
        }
    }

    // Mark the time the last item was added.
    nTimeLastAddSuccessful = GetTimeMillis();
}

void DagWidget::ProcessOrphans()
{
    LOG(DAG, "Dagwidget: mapdeferred size before process orphans %ld", mapDeferredInfo.size());

    LOCK(tailstormForest.cs_forest);
    LOCK(cs_info);

    auto mi = mapDeferredInfo.begin();
    while (mi != mapDeferredInfo.end())
    {
        uint256 hash = mi->first;
        uint256 mininghash = mi->second->mininghash;
        auto blockType = mi->second->blockType;
        auto nBlockHeight = mi->second->nBlockHeight;
        auto nDagHeight = mi->second->nDagHeight;
        auto nTransactions = mi->second->nTransactions;
        auto nBlockSize = mi->second->nBlockSize;
        auto nSequenceId = mi->second->nSequenceId;
        auto vBlockPointsTo = mi->second->vBlockPointsTo;
        bool fHeader = false;
        CBlockHeader header = mi->second->header;

        DbgAssert(!vBlockPointsTo.empty(), );
        const uint256 &prevhash = header.hashPrevBlock;

        uint256 prevDagHash;
        if ((blockType == SUMMARY))
        {
            bool fErased = false;
            std::set<CTreeNodeRef> dag;
            tailstormForest.GetBestDagFor(header.hashPrevBlock, dag);
            if (dag.size() == Params().GetConsensus().tailstorm_k - 1)
            {
                // Get the prevhash that this summary block should point to in the dagviewer. This will
                // be the best dag tip hash.
                prevDagHash = tailstormForest.GetDagTipHash(header.hashPrevBlock);
                if (mapInfo.count(prevDagHash))
                {
                    // add summary block
                    LOG(DAG, "Dagwidget: Adding summary block %s from orphans pointing back to %s", hash.ToString(),
                        prevDagHash.ToString());
                    std::vector<DagWidget::Link> link = {{prevDagHash, true}}; // just use a placeholder for now.
                    AddItem(hash, mininghash, prevDagHash, nDagHeight, nSequenceId, nBlockHeight, nTransactions,
                        nBlockSize, link, false /* ds */, 0 /* nfork */, blockType, fHeader, header);

                    mapDeferredInfo.erase(mi);
                    mi = mapDeferredInfo.begin();
                    fErased = true;
                }
            }
            if (!fErased)
            {
                LOG(DAG,
                    "Dagwidget: Subblocks not in dag yet. Keeping summary block in mapdeffered: %s pointing back to "
                    "%s",
                    hash.ToString(), prevhash.ToString());
                mi++;
            }
        }
        else if (blockType == STORM_BLOCK || blockType == LEGACY_BLOCK)
        {
            bool fHaveAll = true;
            for (auto link : vBlockPointsTo)
            {
                if (!mapInfo.count(link.prevBlock))
                {
                    fHaveAll = false;
                    break;
                }
            }

            if (fHaveAll)
            {
                LOG(DAG, "Dagwidget: Adding subblock or legacy block %s from orphans pointing back to %s",
                    hash.ToString(), vBlockPointsTo[0].prevBlock.ToString());
                AddItem(hash, mininghash, prevhash, nDagHeight, nSequenceId, nBlockHeight, nTransactions, nBlockSize,
                    vBlockPointsTo, false /* ds */, 0 /* nfork */, blockType, fHeader, header);

                mapDeferredInfo.erase(mi);
                mi = mapDeferredInfo.begin();
            }
            else
            {
                LOG(DAG, "Dagwidget: Still in mapdefered: %s pointing back to %s", hash.ToString(),
                    prevhash.ToString());

                mi++;
            }
        }
    }
    LOG(DAG, "Dagwidget: mapdeferred size after process orphans %ld", mapDeferredInfo.size());
}

void DagWidget::Reset()
{
    LOCK(cs_info);
    mapDag.clear();
    mapInfo.clear();
    mapInfoByMiningHash.clear();
    mapDeferredInfo.clear();

    if (scene)
        scene->clear();
}

// for adding text to block rectangles
void DagWidget::AddText(uint256 hash, QPen pen, qreal x, qreal y, uint8_t blockType)
{
    LOCK(cs_info);
    if (!scene)
        return;

    if (blockType == LEGACY_BLOCK || blockType == SUMMARY)
    {
        QFont font("Helvetica", 15);
        font.setHintingPreference(QFont::HintingPreference::PreferNoHinting);
        font.setStyleStrategy(QFont::PreferAntialias);
        font.setKerning(true);
        font.setWeight(60);
        font.setPixelSize(15);
        std::string strHash = hash.ToString();
        std::transform(strHash.begin(), strHash.end(), strHash.begin(), ::toupper);
        std::string strPartHash1(strHash.begin(), strHash.begin() + 4);
        std::string strPartHash2(strHash.begin() + 4, strHash.begin() + 8);

        if (!fQLabelsEnabled)
        {
            QPainterPath path;
            path.addText(x + 12, y + 8, font, QString::fromLocal8Bit(strPartHash1.c_str()));
            path.addText(x + 12, y + 28, font, QString::fromLocal8Bit(strPartHash2.c_str()));
            mapInfo[hash]->itemText = scene->addPath(path, borderPen, charcoalBrush);
        }
        else
        {
            /* TODO: This section of code uses QLabels instead of drawing text directly on the
                      block images. Using QLabels produces better and clearer fonts however it
                      also causes strange problems in Windows which results in a hang or crash. We
                      could just disable this feature for Windows but the fonts already used are adequate
                      and looks quite good on Linux.  So for now we can leave things as they are
                      but also keep this section of code commented out for future research and experimentation.
            */
            QLabel *label = new QLabel();
            label->setStyleSheet("QLabel { background-color : rgba(143, 188, 143, 0); color: black}");

            label->setText(strPartHash1.c_str());
            label->setFont(font);
            label->move(x + 12, y - 7);
            QGraphicsProxyWidget *itemText1 = scene->addWidget(label);
            if (itemText1)
            {
                itemText1->setZValue(1);
                itemText1->update();
            }

            QLabel *label2 = new QLabel();
            label2->setStyleSheet("QLabel { background-color : rgba(143, 188, 143, 0); color: black}");
            label2->setText(strPartHash2.c_str());
            label2->setFont(font);
            label2->move(x + 12, y + 13);
            QGraphicsProxyWidget *itemText2 = scene->addWidget(label2);
            if (itemText2)
            {
                itemText2->setZValue(2);
                itemText2->update();
            }

            if (mapInfo.count(hash))
            {
                mapInfo[hash]->itemText1 = itemText1;
                mapInfo[hash]->itemText2 = itemText2;
            }
        }
    }

    return;
}

int32_t DagWidget::GetNextDagViewerHeight(uint256 &prevDagHash, const CBlockHeader &header)
{
    LOCK(cs_info);
    if (mapInfo.empty())
        return 1;

    // Check in we have all the previous items on screen already. In the case
    // of a Subblock we just need the previous blocks, in the case of a Summary
    // block we need to check all the mining hashes in the minerData to see
    // if all of them are on screen and if so then use the one with the biggest
    // dagviewer height as your previous block.
    bool fHavePrevInfo = true;
    bool fHaveOneItem = false;
    uint32_t nMaxDagHeight = 0;
    if (GetMinerDataVersion(header.minerData) == DEFAULT_MINER_DATA_SUMMARYBLOCK_VERSION)
    {
        uint32_t nPrevDagViewerHeight = 0;
        auto subblockProofs = ParseSummaryBlockMinerData(header.minerData);
        for (const auto &pair : subblockProofs)
        {
            const auto &miningHeaderCommitment = pair.first;
            const auto &nonce = pair.second;
            uint256 mininghash = GetMiningHash(miningHeaderCommitment, nonce);
            if (!mapInfoByMiningHash.count(mininghash))
            {
                fHavePrevInfo = false;
            }
            else
            {
                fHaveOneItem = true;
                nPrevDagViewerHeight = mapInfoByMiningHash[mininghash]->nDagViewerHeight;
                if (nPrevDagViewerHeight > nMaxDagHeight)
                {
                    prevDagHash = mapInfoByMiningHash[mininghash]->blockhash;
                    nMaxDagHeight = nPrevDagViewerHeight;
                }
            }
        }

        if (fHavePrevInfo || (fHaveOneItem && nPrevDagViewerHeight < Params().GetConsensus().tailstorm_k))
        {
            LOG(DAG, "Dagwidget: got next viewer height %ld for summary.", nPrevDagViewerHeight + 1);
            return nMaxDagHeight + 1;
        }
        else
        {
            LOG(DAG, "Dagwidget: prevhash %s not found for SUMMARY !!! - defer in dagviewer",
                header.GetHash().ToString());
            return -1;
        }
    }
    else
    {
        // If this is a subblock then also make sure all the prevhashes in minerData are
        // accounted for in the viewer
        if (GetMinerDataVersion(header.minerData) == DEFAULT_MINER_DATA_SUBBLOCK_VERSION)
        {
            uint32_t nMaxDagViewerHeight = 0;
            auto setPrevHashes = GetPrevHashes(header);
            for (auto &prevhash : setPrevHashes)
            {
                bool fHaveInfo = mapInfo.count(prevhash);
                if (!fHaveInfo && mapInfo.size() > Params().GetConsensus().tailstorm_k)
                {
                    LOG(DAG, "Dagwidget: prevhash %s not found for subblock !!! - defer in dagviewer",
                        prevhash.ToString());
                    return -1;
                }
                if (fHaveInfo && mapInfo[prevhash]->nDagViewerHeight > nMaxDagViewerHeight)
                {
                    prevDagHash = prevhash;
                    nMaxDagViewerHeight = mapInfo[prevhash]->nDagViewerHeight;
                }
            }
            LOG(DAG, "Dagwidget: got next dagviewer subblock height %ld from prevhashes", nMaxDagViewerHeight + 1);
            return nMaxDagViewerHeight + 1;
        }
        else if (mapInfo.count(prevDagHash))
        {
            // Check the prevhash exists for Legacy blocks.
            LOG(DAG, "Dagwidget: got next dagviewer subblock height from prevhash %s : %ld", prevDagHash.ToString(),
                mapInfo[prevDagHash]->nDagViewerHeight + 1);
            return mapInfo[prevDagHash]->nDagViewerHeight + 1;
        }

        return -1;
    }
}

static void BlockTipChanged(DagWidget *dagwidget,
    bool fInitialSync,
    uint32_t nDagHeight,
    uint32_t nSequenceId,
    const CBlockHeader &header,
    bool fSubblock)
{
    if (fInitialSync)
        return;

    uint256 hash = header.GetHash();
    uint256 prevhash = header.hashPrevBlock;
    uint64_t nBlockSize = header.size;
    uint64_t nTransactions = header.txCount;
    uint32_t nBlockHeight = header.height;
    uint256 mininghash = header.GetMiningHash();

    // Create the links object
    auto setPrevHashes = GetPrevHashes(header);
    std::vector<DagWidget::Link> vLinks;
    for (auto &_hash : setPrevHashes)
    {
        DagWidget::Link link = {_hash, true};
        vLinks.push_back(link);
    }

    // Add the item to the viewer
    bool fHeader = false;
    uint256 prevDagHash = prevhash;
    auto blockType = 0;
    if (GetMinerDataVersion(header.minerData) != 0)
    {
        blockType = fSubblock ? DagWidget::STORM_BLOCK : DagWidget::SUMMARY;
        auto nNextDagViewerHeight = dagwidget->GetNextDagViewerHeight(prevDagHash, header);
        if (!fSubblock)
        {
            // Special case for summary blocks. The vLinks will point back to the best dag tip
            // rather than the summary block's prevhash.
            vLinks = {{prevDagHash, true}};
        }

        if (nNextDagViewerHeight == -1)
        {
            // defer summary block
            if (!fSubblock)
            {
                LOG(DAG, "Dagwidget: Deferring summary block in dagwidget %s which points to %s", hash.ToString(),
                    prevDagHash.ToString());
            }
            else
            {
                LOG(DAG, "Dagwidget: Deferring subblock in dagwidget %s", hash.ToString());
            }

            dagwidget->DeferItem(hash, mininghash, prevDagHash, nDagHeight, nSequenceId, nBlockHeight, nTransactions,
                nBlockSize, vLinks, false /* ds */, 0 /* nfork */, blockType, fHeader, header);

            return;
        }
    }
    else
    {
        blockType = DagWidget::LEGACY_BLOCK;
        auto nNextDagViewerHeight = dagwidget->GetNextDagViewerHeight(prevDagHash, header);
        if (nNextDagViewerHeight == -1)
        {
            LOG(DAG, "Dagwidget: Deferring legacy block in dagwidget %s which points to %s", hash.ToString(),
                prevDagHash.ToString());
            dagwidget->DeferItem(hash, mininghash, prevDagHash, nDagHeight, nSequenceId, nBlockHeight, nTransactions,
                nBlockSize, vLinks, false /* ds */, 0 /* nfork */, blockType, fHeader, header);

            return;
        }
    }
    bool fDoubleSpend = false;
    uint32_t nFork = 0; // not really relevant anymore and could take out.
    // NOTE: must use a lamba because of Qt's 10 parameter limit when using invokeMethod.
    QMetaObject::invokeMethod(
        dagwidget,
        [=]()
        {
            if (dagwidget)
            {
                dagwidget->AddItem(hash, mininghash, prevDagHash, nDagHeight, nSequenceId, nBlockHeight, nTransactions,
                    nBlockSize, vLinks, fDoubleSpend, nFork, blockType, fHeader, header);
            }
        },
        Qt::QueuedConnection);

    QMetaObject::invokeMethod(
        dagwidget,
        [=]()
        {
            if (dagwidget)
            {
                dagwidget->ProcessOrphans();
            }
        },
        Qt::QueuedConnection);
}

static void BlockHeaderChanged(DagWidget *dagwidget,
    bool fInitialSync,
    uint32_t nDagHeight,
    uint32_t nSequenceId,
    const CBlockHeader &header,
    bool fSubblock)
{
    if (fInitialSync)
        return;

    uint256 hash = header.GetHash();
    uint256 prevhash = header.hashPrevBlock;
    uint64_t nBlockSize = header.size;
    uint64_t nTransactions = header.txCount;
    uint32_t nBlockHeight = header.height;
    uint256 mininghash = header.GetMiningHash();

    // Create the links object
    auto setPrevHashes = GetPrevHashes(header);
    std::vector<DagWidget::Link> vLinks;
    for (auto &_hash : setPrevHashes)
    {
        DagWidget::Link link = {_hash, true};
        vLinks.push_back(link);
    }

    // Add the item to the viewer
    bool fHeader = true;
    uint256 prevDagHash = prevhash;
    auto blockType = 0;
    if (GetMinerDataVersion(header.minerData) != 0)
    {
        auto nNextDagViewerHeight = dagwidget->GetNextDagViewerHeight(prevDagHash, header);
        if (!fSubblock)
        {
            // Special case for summary blocks. The vLinks will point back to the best dag tip
            // rather than the summary block's prevhash.
            vLinks = {{prevDagHash, true}};
        }

        blockType = fSubblock ? DagWidget::STORM_BLOCK : DagWidget::SUMMARY;
        if (nNextDagViewerHeight == -1)
        {
            // defer summary block
            if (!fSubblock)
            {
                // Special case for summary blocks. The vLinks will point back to the best dag tip
                // rather than the summary block's prevhash.
                vLinks = {{prevDagHash, true}};
                LOG(DAG, "Dagwidget: Deferring summary block in dagwidget %s which points to %s", hash.ToString(),
                    prevDagHash.ToString());
            }
            else
            {
                LOG(DAG, "Dagwidget: Deferring subblock in dagwidget %s", hash.ToString());
            }

            dagwidget->DeferItem(hash, mininghash, prevDagHash, nDagHeight, nSequenceId, nBlockHeight, nTransactions,
                nBlockSize, vLinks, false /* ds */, 0 /* nfork */, blockType, fHeader, header);

            return;
        }
    }
    else
    {
        blockType = DagWidget::LEGACY_BLOCK;
        auto nNextDagViewerHeight = dagwidget->GetNextDagViewerHeight(prevDagHash, header);
        if (nNextDagViewerHeight == -1)
        {
            LOG(DAG, "Dagwidget: Deferring legacy block in dagwidget %s which points to %s", hash.ToString(),
                prevDagHash.ToString());
            dagwidget->DeferItem(hash, mininghash, prevDagHash, nDagHeight, nSequenceId, nBlockHeight, nTransactions,
                nBlockSize, vLinks, false /* ds */, 0 /* nfork */, blockType, fHeader, header);

            return;
        }
    }

    bool fDoubleSpend = false;
    uint32_t nFork = 0; // not really relevant anymore and could take out.
    // NOTE: must use a lamba because of Qt's 10 parameter limit when using invokeMethod.
    QMetaObject::invokeMethod(
        dagwidget,
        [=]()
        {
            if (dagwidget)
            {
                dagwidget->AddItem(hash, mininghash, prevDagHash, nDagHeight, nSequenceId, nBlockHeight, nTransactions,
                    nBlockSize, vLinks, fDoubleSpend, nFork, blockType, fHeader, header);
            }
        },
        Qt::QueuedConnection);

    QMetaObject::invokeMethod(
        dagwidget,
        [=]()
        {
            if (dagwidget)
            {
                dagwidget->ProcessOrphans();
            }
        },
        Qt::QueuedConnection);
}

static void ResetViewer(DagWidget *dagwidget)
{
    QMetaObject::invokeMethod(
        dagwidget,
        [=]()
        {
            if (dagwidget)
            {
                dagwidget->Reset();
            }
        },
        Qt::QueuedConnection);
}

void DagWidget::SubscribeToCoreSignals()
{
    // Connect core signals to block viewer
    blockTipConn = uiInterface.NotifyBlockTipDag.connect(boost::bind(
        BlockTipChanged, this, boost::arg<1>(), boost::arg<2>(), boost::arg<3>(), boost::arg<4>(), boost::arg<5>()));
    headerTipConn = uiInterface.NotifyHeaderTipDag.connect(boost::bind(
        BlockHeaderChanged, this, boost::arg<1>(), boost::arg<2>(), boost::arg<3>(), boost::arg<4>(), boost::arg<5>()));
    resetConn = uiInterface.ResetDagViewer.connect(boost::bind(ResetViewer, this));
}

void DagWidget::UnsubscribeFromCoreSignals()
{
    // Disconnect signals from client
    blockTipConn.disconnect();
    headerTipConn.disconnect();
    resetConn.disconnect();
}

void DagWidget::RemoveHighlight()
{
    LOCK(cs_info);
    if (scene && itemHighlight)
    {
        scene->removeItem(itemHighlight);
        delete itemHighlight;
        itemHighlight = nullptr;
        pSelected = nullptr;
    }
}

void DagWidget::ScaleUp()
{
    LOCK(cs_info);
    if (!view)
        return;
    qreal scale = (qreal)4 / 3;
    view->scale(scale, scale);
}

void DagWidget::ScaleDown()
{
    LOCK(cs_info);
    if (!view)
        return;
    qreal scale = (qreal)3 / 4;
    view->scale(scale, scale);
}

void DagWidget::ShowPauseButton()
{
    // This function sends a SIGNAL back to the RPC Console buttons
    // which tell it which button text to show.
    LOCK(cs_info);
    if (!view)
        return;
    fPause = false;
    view->horizontalScrollBar()->setSliderPosition(view->horizontalScrollBar()->maximum());
    if (buttonPauseContinue)
    {
        buttonPauseContinue->setText("||");
        buttonPauseContinue->setToolTip("Pause block tracking");
    }
}

void DagWidget::ShowContinueButton()
{
    // This function sends a SIGNAL back to the RPC Console buttons
    // which tell it which button text to show.
    LOCK(cs_info);
    fPause = true;
    if (buttonPauseContinue)
    {
        buttonPauseContinue->setText(">>");
        buttonPauseContinue->setToolTip("Continue block tracking");
    }
}

void DagWidget::ShowPauseContinueButtons()
{
    // This is for processing the SIGNAL which comes from
    // the RPC Console button clicks.
    LOCK(cs_info);
    if (!view)
        return;

    if (!fPause) // Switch from pause button to continue button
    {
        ShowContinueButton();
    }
    else // switch from continue button to pause button
    {
        ShowPauseButton();
    }
}

// Simulation1 data
void DagWidget::SetupSimulation1()
{
    std::vector<Link> a;
    uint256 blockhash1 = GetRandHash();
    mapSimulation1[1][blockhash1] = a;

    uint256 blockhash2 = GetRandHash();
    std::vector<Link> b = {{blockhash1, true}};
    mapSimulation1[2][blockhash2] = b;

    uint256 blockhash3 = GetRandHash();
    std::vector<Link> c = {{blockhash2, true}};
    mapSimulation1[3][blockhash3] = c;

    uint256 blockhash4 = GetRandHash();
    std::vector<Link> d = {{blockhash3, true}};
    mapSimulation1[4][blockhash4] = d;

    uint256 blockhash5 = GetRandHash();
    std::vector<Link> e = {{blockhash4, true}};
    mapSimulation1[5][blockhash5] = e;
    std::vector<Link> f = {{blockhash5, true}};

    uint256 blockhash6a = GetRandHash();
    uint256 blockhash6b = GetRandHash();
    uint256 blockhash6c = GetRandHash();
    uint256 blockhash6d = GetRandHash();
    uint256 blockhash6e = GetRandHash();
    mapSimulation1[6][blockhash6a] = f;
    mapSimulation1[6][blockhash6b] = f;
    mapSimulation1[6][blockhash6c] = f;
    mapSimulation1[6][blockhash6d] = f;
    mapSimulation1[6][blockhash6e] = f;

    std::vector<Link> g = {{blockhash6b, true}};
    uint256 blockhash7a = GetRandHash();
    mapSimulation1[7][blockhash7a] = g;

    uint256 blockhash7b = GetRandHash();
    std::vector<Link> h = {{blockhash6a, true}};
    mapSimulation1[7][blockhash7b] = h;

    uint256 blockhash7c = GetRandHash();
    std::vector<Link> i = {{blockhash6c, true}, {blockhash6d, true}, {blockhash6e, true}};
    mapSimulation1[7][blockhash7c] = i;

    uint256 blockhash8 = GetRandHash();
    std::vector<Link> j = {{blockhash7a, true}, {blockhash7b, true}, {blockhash7c, true}};
    mapSimulation1[8][blockhash8] = j;

    uint256 blockhash9a = GetRandHash();
    uint256 blockhash9b = GetRandHash();
    std::vector<Link> k = {{blockhash8, true}};
    mapSimulation1[9][blockhash9a] = k;
    mapSimulation1[9][blockhash9b] = k;

    uint256 blockhash10 = GetRandHash();
    std::vector<Link> l = {{blockhash9a, true}, {blockhash9b, true}};
    mapSimulation1[10][blockhash10] = l;

    uint256 blockhash11 = GetRandHash();
    std::vector<Link> m = {{blockhash9b, false}, {blockhash10, true}};
    mapSimulation1[11][blockhash11] = m;

    uint256 blockhash12a = GetRandHash();
    uint256 blockhash12b = GetRandHash();
    uint256 blockhash12c = GetRandHash();
    std::vector<Link> n = {{blockhash11, true}};
    mapSimulation1[12][blockhash12b] = n;
    mapSimulation1[12][blockhash12a] = n;
    mapSimulation1[12][blockhash12c] = n;

    uint256 blockhash13 = GetRandHash();
    std::vector<Link> o = {{blockhash12c, true}, {blockhash12b, true}, {blockhash12a, true}};
    mapSimulation1[13][blockhash13] = o;

    uint256 blockhash14 = GetRandHash();
    uint256 blockhash14a = GetRandHash();
    std::vector<Link> p = {{blockhash13, true}};
    mapSimulation1[14][blockhash14] = p;
    mapSimulation1[14][blockhash14a] = p;

    uint256 blockhash15 = GetRandHash();
    std::vector<Link> q = {{blockhash14, true}};
    mapSimulation1[15][blockhash15] = q;

    uint256 blockhash15a = GetRandHash();
    std::vector<Link> q2 = {{blockhash14a, true}};
    mapSimulation1[15][blockhash15a] = q2;

    uint256 blockhash16 = GetRandHash();
    std::vector<Link> r = {{blockhash15, true}};
    mapSimulation1[16][blockhash16] = r;

    uint256 blockhash17 = GetRandHash();
    std::vector<Link> s = {{blockhash16, true}};
    mapSimulation1[17][blockhash17] = s;
}

// Simulation2 data
void DagWidget::SetupSimulation2()
{
    std::vector<Link> a;
    uint256 blockhash1 = GetRandHash();
    mapSimulation2[1][blockhash1] = a;

    uint256 blockhash2 = GetRandHash();
    std::vector<Link> b = {{blockhash1, true}};
    mapSimulation2[2][blockhash2] = b;

    uint256 blockhash3 = GetRandHash();
    std::vector<Link> c = {{blockhash2, true}};
    mapSimulation2[3][blockhash3] = c;

    uint256 blockhash4 = GetRandHash();
    std::vector<Link> d = {{blockhash3, true}};
    mapSimulation2[4][blockhash4] = d;

    uint256 blockhash5 = GetRandHash();
    std::vector<Link> e = {{blockhash4, true}};
    mapSimulation2[5][blockhash5] = e;
    std::vector<Link> f = {{blockhash5, true}};

    uint256 blockhash6a = GetRandHash();
    uint256 blockhash6b = GetRandHash();
    uint256 blockhash6c = GetRandHash();
    mapSimulation2[6][blockhash6a] = f;
    mapSimulation2[6][blockhash6b] = f;
    mapSimulation2[6][blockhash6c] = f;

    std::vector<Link> g = {{blockhash6a, true}};
    uint256 blockhash7a = GetRandHash();
    mapSimulation2[7][blockhash7a] = g;

    uint256 blockhash8 = GetRandHash();
    std::vector<Link> j = {{blockhash7a, true}};
    mapSimulation2[8][blockhash8] = j;


    uint256 blockhash9a = GetRandHash();
    uint256 blockhash9b = GetRandHash();
    std::vector<Link> k = {{blockhash8, true}};
    mapSimulation2[9][blockhash9a] = k;
    mapSimulation2[9][blockhash9b] = k;

    uint256 blockhash10 = GetRandHash();
    std::vector<Link> l = {{blockhash9a, true}};
    mapSimulation2[10][blockhash10] = l;

    uint256 blockhash11 = GetRandHash();
    std::vector<Link> m = {{blockhash9b, true}, {blockhash10, true}};
    mapSimulation2[11][blockhash11] = m;

    uint256 blockhash12a = GetRandHash();
    uint256 blockhash12b = GetRandHash();
    uint256 blockhash12c = GetRandHash();
    std::vector<Link> n = {{blockhash11, true}};
    mapSimulation2[12][blockhash12b] = n;
    mapSimulation2[12][blockhash12a] = n;
    mapSimulation2[12][blockhash12c] = n;

    uint256 blockhash13 = GetRandHash();
    std::vector<Link> o = {{blockhash12c, true}, {blockhash12b, true}, {blockhash12a, true}};
    mapSimulation2[13][blockhash13] = o;

    uint256 blockhash14 = GetRandHash();
    uint256 blockhash14a = GetRandHash();
    std::vector<Link> p = {{blockhash13, true}};
    mapSimulation2[14][blockhash14] = p;
    mapSimulation2[14][blockhash14a] = p;

    uint256 blockhash15 = GetRandHash();
    std::vector<Link> q = {{blockhash14, true}, {blockhash14a, true}};
    mapSimulation2[15][blockhash15] = q;
}


void DagWidget::SetupSimulation5()
{
    enum
    {
        HEADER = 0,
        BLOCK = 1
    };

    // Add headers
    /*
    uint256 prevhash;
    uint32_t blocknum = 0;
    uint32_t blockheight = -1;
    for (uint32_t count = 1; count <= 96; count++)
    {
        blocknum++;
        blockheight++;
        uint256 hash = GetRandHash();
        std::vector<Link> link = {{prevhash, true}};
        SimInfo info_headers{hash, blockheight , link, HEADER, false, 0, LEGACY_BLOCK};
        vSimulation5.push_back(info_headers);
        prevhash = hash;
    }
    */
    std::vector<Link> a;
    uint256 blockhash1 = GetRandHash();
    SimInfo info1{blockhash1, 1, a, HEADER, false, 0, LEGACY_BLOCK};
    vSimulation5.push_back(info1);
    SimInfo info1a{blockhash1, 1, a, BLOCK, false, 0, LEGACY_BLOCK};
    vSimulation5.push_back(info1a);

    uint256 blockhash2 = GetRandHash();
    std::vector<Link> b = {{blockhash1, true}};
    SimInfo info2{blockhash2, 2, b, BLOCK, false, 0, LEGACY_BLOCK};
    vSimulation5.push_back(info2);
    SimInfo info2a{blockhash2, 2, b, BLOCK, false, 0, LEGACY_BLOCK};
    vSimulation5.push_back(info2a);
    SimInfo info2b{blockhash2, 2, b, HEADER, false, 0, LEGACY_BLOCK};
    vSimulation5.push_back(info2b);

    uint256 blockhash3 = GetRandHash();
    std::vector<Link> c = {{blockhash2, true}};
    SimInfo info3{blockhash3, 3, c, BLOCK, false, 0, LEGACY_BLOCK};
    vSimulation5.push_back(info3);
    SimInfo info3a{blockhash3, 3, c, BLOCK, false, 0, LEGACY_BLOCK};
    vSimulation5.push_back(info3a);

    uint256 blockhash1b = GetRandHash();
    SimInfo info1b{blockhash1b, 1, a, HEADER, false, 0, LEGACY_BLOCK};
    vSimulation5.push_back(info1b);
    SimInfo info1c{blockhash1b, 1, a, BLOCK, false, 0, LEGACY_BLOCK};
    vSimulation5.push_back(info1c);
    uint256 blockhash1c = GetRandHash();
    SimInfo info1d{blockhash1c, 1, a, BLOCK, false, 0, LEGACY_BLOCK};
    vSimulation5.push_back(info1d);

    uint256 blockhash2b = GetRandHash();
    std::vector<Link> bb = {{blockhash1b, true}};
    SimInfo info2c{blockhash2b, 2, bb, BLOCK, false, 0, LEGACY_BLOCK};
    vSimulation5.push_back(info2c);

    uint256 blockhash4 = GetRandHash();
    std::vector<Link> d = {{blockhash3, true}};
    SimInfo info4a{blockhash4, 4, d, HEADER, false, 0, LEGACY_BLOCK};
    vSimulation5.push_back(info4a);
    vSimulation5.push_back(info4a);
    vSimulation5.push_back(info4a);
    SimInfo info4{blockhash4, 4, d, BLOCK, false, 0, LEGACY_BLOCK};
    vSimulation5.push_back(info4);

    uint256 blockhash5 = GetRandHash();
    std::vector<Link> e = {{blockhash4, true}};
    SimInfo info5{blockhash5, 5, e, BLOCK, false, 0, LEGACY_BLOCK};
    vSimulation5.push_back(info5);
    SimInfo info5a{blockhash5, 5, e, HEADER, false, 0, LEGACY_BLOCK};
    vSimulation5.push_back(info5a);
    SimInfo info5b{blockhash5, 5, e, BLOCK, false, 0, LEGACY_BLOCK};
    vSimulation5.push_back(info5b);
    SimInfo info5c{blockhash5, 5, e, HEADER, false, 0, LEGACY_BLOCK};
    vSimulation5.push_back(info5c);

    std::vector<Link> f = {{blockhash5, true}};
    uint256 blockhash6a = GetRandHash();
    uint256 blockhash6b = GetRandHash();
    uint256 blockhash6c = GetRandHash();
    uint256 blockhash6d = GetRandHash();
    uint256 blockhash6e = GetRandHash();
    uint256 blockhash6f = GetRandHash();
    uint256 blockhash6g = GetRandHash();
    uint256 blockhash6h = GetRandHash();
    uint256 blockhash6i = GetRandHash();
    SimInfo info6{blockhash6a, 6, f, BLOCK, false, 0, LEGACY_BLOCK};
    vSimulation5.push_back(info6);
    SimInfo info6a{blockhash6b, 6, f, BLOCK, false, 0, LEGACY_BLOCK};
    vSimulation5.push_back(info6a);
    SimInfo info6b{blockhash6c, 6, f, BLOCK, false, 0, LEGACY_BLOCK};
    vSimulation5.push_back(info6b);
    SimInfo info6c{blockhash6d, 6, f, BLOCK, false, 0, LEGACY_BLOCK};
    vSimulation5.push_back(info6c);
    SimInfo info6d{blockhash6e, 6, f, BLOCK, false, 0, LEGACY_BLOCK};
    vSimulation5.push_back(info6d);
    SimInfo info6e{blockhash6f, 6, f, BLOCK, false, 0, LEGACY_BLOCK};
    vSimulation5.push_back(info6e);
    SimInfo info6f{blockhash6g, 6, f, BLOCK, false, 0, LEGACY_BLOCK};
    vSimulation5.push_back(info6f);
    SimInfo info6g{blockhash6h, 6, f, BLOCK, false, 0, LEGACY_BLOCK};
    vSimulation5.push_back(info6g);
    SimInfo info6h{blockhash6i, 6, f, BLOCK, false, 0, LEGACY_BLOCK};
    vSimulation5.push_back(info6h);

    std::vector<Link> g = {{blockhash6b, true}};
    uint256 blockhash7a = GetRandHash();
    SimInfo info7{blockhash7a, 7, g, BLOCK, false, 0, LEGACY_BLOCK};
    vSimulation5.push_back(info7);

    uint256 blockhash7b = GetRandHash();
    std::vector<Link> h = {{blockhash6a, true}};
    SimInfo info7b{blockhash7b, 7, h, BLOCK, false, 0, LEGACY_BLOCK};
    vSimulation5.push_back(info7b);

    uint256 blockhash7c = GetRandHash();
    std::vector<Link> i = {{blockhash6c, true}};
    SimInfo info7c{blockhash7c, 7, i, BLOCK, false, 0, LEGACY_BLOCK};
    vSimulation5.push_back(info7c);

    uint256 blockhash8 = GetRandHash();
    std::vector<Link> j = {{blockhash7a, true}, {blockhash7b, false}, {blockhash7c, false}};
    SimInfo info8{blockhash8, 8, j, BLOCK, false, 0, LEGACY_BLOCK};
    vSimulation5.push_back(info8);

    uint256 blockhash9a = GetRandHash();
    uint256 blockhash9b = GetRandHash();
    std::vector<Link> k = {{blockhash8, true}};
    SimInfo info9{blockhash9a, 9, k, HEADER, false, 0, LEGACY_BLOCK};
    vSimulation5.push_back(info9);
    SimInfo info9a{blockhash9b, 9, k, HEADER, false, 0, LEGACY_BLOCK};
    vSimulation5.push_back(info9a);
    SimInfo info9b{blockhash9a, 9, k, BLOCK, false, 0, LEGACY_BLOCK};
    vSimulation5.push_back(info9b);
    SimInfo info9c{blockhash9b, 9, k, BLOCK, false, 0, LEGACY_BLOCK};
    vSimulation5.push_back(info9c);


    uint256 blockhash10 = GetRandHash();
    std::vector<Link> l = {{blockhash9a, true}};
    SimInfo info10{blockhash10, 10, l, HEADER, false, 0, LEGACY_BLOCK};
    vSimulation5.push_back(info10);

    uint256 blockhash11 = GetRandHash();
    std::vector<Link> m = {{blockhash9b, false}, {blockhash10, true}};
    SimInfo info11{blockhash11, 11, m, HEADER, false, 0, LEGACY_BLOCK};
    vSimulation5.push_back(info11);

    vSimulation5.push_back(info10);
    vSimulation5.push_back(info10);
    vSimulation5.push_back(info11);
    vSimulation5.push_back(info10);
    vSimulation5.push_back(info11);

    SimInfo info10a{blockhash10, 10, l, BLOCK, false, 0, LEGACY_BLOCK};
    vSimulation5.push_back(info10a);
    SimInfo info11a{blockhash11, 11, m, BLOCK, false, 0, LEGACY_BLOCK};
    vSimulation5.push_back(info11a);

    // Add connections to older blocks and headers
    uint256 blockhash7d = GetRandHash();
    SimInfo info7d{blockhash7d, 7, i, HEADER, false, 0, LEGACY_BLOCK};
    vSimulation5.push_back(info7d);
    uint256 blockhash8d = GetRandHash();
    std::vector<Link> i2 = {{blockhash7d, true}};
    SimInfo info8d{blockhash8d, 8, i2, HEADER, false, 0, LEGACY_BLOCK};
    vSimulation5.push_back(info8d);
    uint256 blockhash9d = GetRandHash();
    std::vector<Link> i3 = {{blockhash8d, true}};
    SimInfo info9d{blockhash9d, 9, i3, HEADER, false, 0, LEGACY_BLOCK};
    vSimulation5.push_back(info9d);

    SimInfo info7d2{blockhash7d, 7, i, BLOCK, false, 0, LEGACY_BLOCK};
    vSimulation5.push_back(info7d2);
    SimInfo info8d2{blockhash8d, 8, i2, BLOCK, false, 0, LEGACY_BLOCK};
    vSimulation5.push_back(info8d2);

    // Add a thousand headers
    /*
    uint256 prevhash = blockhash8d;
    uint32_t blocknum = 25;
    uint32_t blockheight = 8;
    for (uint32_t count = 1; count <= 1000; count++)
    {
        blocknum++;
        blockheight++;
        uint256 hash = GetRandHash();
        std::vector<Link> link = {{prevhash, true}};
        SimInfo info_headers{hash, blocknum, blockheight , link, HEADER, false, 0, LEGACY_BLOCK};
        vSimulation5.push_back(info_headers);
        prevhash = hash;
    }
    */
}

void DagWidget::dagSimulation()
{
    static int item = 1;
    static int next = 0;

    static int first = 0;
    first++;
    if (first < 2)
        return;

    bool ds = false;
    uint32_t nFork = 0;
    uint256 mininghash;
    CBlockHeader header;

    std::map<uint256, uint64_t> mapDagHeight;

    // How many polltimer iterations to wait before starting the simluation.
    // Usefull when wanting to start a video recording.
    uint32_t nDelayIterations = 0;
    static uint32_t iteration = 0;

    if (nRunSimulation == 1)
    {
        iteration++;
        if (iteration < nDelayIterations)
            return;

        if (!mapSimulation1.count(item))
            return;

        for (auto &k : mapSimulation1[item])
        {
            next++;
            ds = false;
            if (next == 17)
            {
                ds = false;
                nFork = 1;
            }
            else
            {
                ds = false;
                nFork = 0;
            }

            uint256 prevblock;
            for (Link link : k.second)
            {
                if (link.fHardLink)
                {
                    prevblock = link.prevBlock;
                }
            }
            printf("block height %d next %d ds %d\n", item, next, ds);

            if (item == 15)
            {
                AddItem(k.first, mininghash, prevblock, item, next, item, 0, 0, k.second, ds, nFork, SUMMARY, false,
                    header);
            }
            else
            {
                AddItem(k.first, mininghash, prevblock, item, next, item, 0, 0, k.second, ds, nFork, STORM_BLOCK, true,
                    header);
                AddItem(k.first, mininghash, prevblock, item, next, item, 0, 0, k.second, ds, nFork, STORM_BLOCK, false,
                    header);
            }
        }
        item++;
    }

    if (nRunSimulation == 2 || nRunSimulation == 3 || nRunSimulation == 4)
    {
        if (!mapSimulation2.count(item))
            return;

        for (auto &k : mapSimulation2[item])
        {
            next++;
            ds = false;
            if (next == 37)
            {
                ds = true;
                nFork = 1;
            }
            else
            {
                ds = false;
                nFork = 0;
            }

            uint256 prevblock;
            for (Link link : k.second)
            {
                if (link.fHardLink)
                {
                    prevblock = link.prevBlock;
                }
            }
            printf("block height %d next %d ds %d\n", item, next, ds);

            if (item >= 9)
            {
                AddItem(k.first, mininghash, prevblock, item, next, 0, 0, 0, k.second, ds, nFork, STORM_BLOCK, false,
                    header);
            }
            else if (nRunSimulation == 2)
            {
                AddItem(k.first, mininghash, prevblock, item, next, 0, 0, 0, k.second, ds, nFork, LEGACY_BLOCK, true,
                    header);
                AddItem(k.first, mininghash, prevblock, item, next, 0, 0, 0, k.second, ds, nFork, LEGACY_BLOCK, false,
                    header);
            }
            else if (nRunSimulation == 3)
            {
                AddItem(
                    k.first, mininghash, prevblock, item, next, 0, 0, 0, k.second, ds, nFork, SUMMARY, true, header);
                AddItem(
                    k.first, mininghash, prevblock, item, next, 0, 0, 0, k.second, ds, nFork, SUMMARY, false, header);
            }
            else if (nRunSimulation == 4)
            {
                if (item <= 3)
                {
                    AddItem(k.first, mininghash, prevblock, item, next, 0, 0, 0, k.second, ds, nFork, LEGACY_BLOCK,
                        true, header);
                    AddItem(k.first, mininghash, prevblock, item, next, 0, 0, 0, k.second, ds, nFork, LEGACY_BLOCK,
                        false, header);
                }
                else
                {
                    AddItem(k.first, mininghash, prevblock, item, next, 0, 0, 0, k.second, ds, nFork, SUMMARY, true,
                        header);
                    AddItem(k.first, mininghash, prevblock, item, next, 0, 0, 0, k.second, ds, nFork, SUMMARY, false,
                        header);
                }
            }
        }
        item++;
    }

    if (nRunSimulation == 5)
    {
        if ((size_t)item > vSimulation5.size())
            return;

        SimInfo info = vSimulation5[item - 1];
        uint256 prevblock;
        for (auto link : info.vBlockPointsTo)
        {
            if (link.fHardLink)
            {
                prevblock = link.prevBlock;
            }
        }
        printf("adding block height %d have block %d\n", info.nDagViewerHeight, info.fHaveBlock);
        AddItem(info.blockhash, mininghash, prevblock, info.nDagViewerHeight, item, 0, 0, 0, info.vBlockPointsTo,
            info.fDoubleSpend, info.nFork, info.blockType, !info.fHaveBlock, header);

        item++;
    }
}
