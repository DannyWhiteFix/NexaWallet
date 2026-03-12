// Copyright (c) 2015-2024 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef DAGWIDGET_H
#define DAGWIDGET_H

#include "chainparams.h"
#include "sync.h"
#include "ui_blockdescdialog.h"
#include "ui_interface.h"
#include "uint256.h"

#include <memory>

#include <QDialog>
#include <QGraphicsView>
#include <QPainterPath>
#include <QPushButton>
#include <QTimer>

class DagWidget;

namespace Ui
{
class BlockDescDialog;
}

/** Dialog showing block details. */
class BlockDescDialog : public QDialog
{
    Q_OBJECT

    friend DagWidget;

public:
    explicit BlockDescDialog(QString *desc, QWidget *parent = nullptr, DagWidget *dagwidget = nullptr);
    ~BlockDescDialog();

private:
    Ui::BlockDescDialog *ui;
    DagWidget *_dagwidget = nullptr;

private Q_SLOTS:
    void hideEvent(QHideEvent *event);
};

class DagWidget : public QWidget
{
    Q_OBJECT

    friend BlockDescDialog;

public:
    explicit DagWidget(QWidget *parent = nullptr);
    ~DagWidget();

    void resizeGraphicsView(QWidget *console);

    enum
    {
        STORM_BLOCK = 0,
        SUMMARY = 1,
        LEGACY_BLOCK = 2,
        ORPHAN_BLOCK = 3
    };

    struct Link
    {
        uint256 prevBlock;
        bool fHardLink = false;
    };

    struct ItemInfo
    {
        uint256 blockhash;
        uint256 mininghash;
        uint32_t nDagViewerHeight = 0;
        uint32_t nDagHeight = 0;
        uint32_t nSequenceId = 0;
        uint32_t nBlockHeight = 0;
        uint64_t nTransactions = 0;
        uint64_t nBlockSize = 0;
        qreal x = 0;
        qreal y = 0;
        qreal itemWidth = 0;
        qreal itemHeight = 0;
        std::vector<Link> vBlockPointsTo;
        bool fIsChainTip = true;
        bool fHasDoubleSpend = false;
        uint8_t blockType = 0;
        bool fHaveBlock = false;
        CBlockHeader header;

        QGraphicsPathItem *item = nullptr;
        QGraphicsPathItem *itemText = nullptr;
        QGraphicsProxyWidget *itemText1 = nullptr;
        QGraphicsProxyWidget *itemText2 = nullptr;
        QGraphicsLineItem *litem = nullptr;
    };

    // Defer a new block item. To be added to the viewer when
    // the previous blocks finally arrive and are added first.
    void DeferItem(uint256 hash,
        uint256 mininghash,
        uint256 prevhash,
        uint32_t nDagHeight,
        uint32_t nSequenceId,
        uint32_t nBlockHeight,
        uint64_t nTransactions,
        uint64_t nBlockSize,
        std::vector<Link> &_vpointsto,
        bool fDoubleSpend,
        uint8_t blockType,
        bool fHeader,
        const CBlockHeader &header);

    // Add a new block item to the viewer
    void AddItem(uint256 hash,
        uint256 mininghash,
        uint256 prevhash,
        uint32_t nDagHeight,
        uint32_t nSequenceId,
        uint32_t nBlockHeight,
        uint64_t nTransactions,
        uint64_t nBlockSize,
        std::vector<Link> _vpointsto,
        bool fDoubleSpend,
        uint8_t blockType,
        bool fHeader,
        const CBlockHeader &header);

    // Get the next height in the dag which we use to position the item
    // in the dagviewer's scene.
    int32_t GetNextDagViewerHeight(uint256 &prevDagHash, const CBlockHeader &header, const uint32_t blockType);

    // Try to connect any orphaned items.
    void ProcessOrphans();

    // Reset the dag viewer
    void Reset();

private:
    QWidget *_parent; // pointer to the layout
    BlockDescDialog *uiBlockDesc = nullptr; // block description message box

    CCriticalSection cs_info;

    // Graphics view pointers
    QGraphicsScene *scene GUARDED_BY(cs_info);
    QGraphicsView *view GUARDED_BY(cs_info);

    // Data structures for holding graphic items and related data
    std::map<uint256, std::shared_ptr<ItemInfo> > mapInfo GUARDED_BY(cs_info);
    std::map<uint256, std::shared_ptr<ItemInfo> > mapOrphanInfo GUARDED_BY(cs_info);
    std::map<uint256, std::shared_ptr<ItemInfo> > mapInfoByMiningHash GUARDED_BY(cs_info);
    std::map<uint256, std::shared_ptr<ItemInfo> > mapDeferredInfo GUARDED_BY(cs_info);
    std::map<uint32_t, std::vector<std::shared_ptr<ItemInfo> > > mapDag GUARDED_BY(cs_info);

    // The time the last item was successfully connected to the dag viewer
    int64_t nTimeLastAddSuccessful GUARDED_BY(cs_info) = 0;

    // The last block item which was clicked on.
    std::shared_ptr<ItemInfo> pSelected GUARDED_BY(cs_info) = nullptr;
    // The current highlighted block item;
    QGraphicsPathItem *itemHighlight GUARDED_BY(cs_info) = nullptr;

    // Track the x-coord where we should center the view on
    qreal xCenter GUARDED_BY(cs_info) = 0;
    const qreal xOffset = 130; // pixel offset from the end of the view

    // Is the viewer activated and ready to show blocks.
    bool fStartBlockViewer GUARDED_BY(cs_info) = false;

    // Did we pause tracking new blocks
    bool fPause GUARDED_BY(cs_info) = false;

    // Last summary dag viewer height.
    uint32_t nLastSummaryDagViewerHeight GUARDED_BY(cs_info) = 0;

    // pens and brushes
    QPen borderPen;
    QPen thickBorderPen;
    QPen dashedLinePen;
    QPen widgetBorderPen;

    QBrush greenBrush;
    QBrush greyBrush;
    QBrush redBrush;
    QBrush blueBrush;
    QBrush goldBrush;
    QBrush violetBrush;
    QBrush whiteBrush;
    QBrush blackBrush;
    QBrush steelBlueBrush;
    QBrush charcoalBrush;

    // block dimensions
    const qreal subblockWidth = 28;
    const qreal subblockHeight = 24;
    const qreal summaryHeight = 100;
    const qreal summaryWidth = 60;
    const qreal legacyHeight = 60;
    const qreal legacyWidth = 60;
    const qreal distance = 28;
    const qreal radius = 5;

    /** The view width (in pixels) of the graphics scene. */
    const qreal DEFAULT_WIDTH_OF_VIEW = 100 * 1000;
    /** The maximum number of blocks we keep in the graphics scene (make it a little bigger than the view can hold) */
    const size_t DEFAULT_MAX_BLOCKS = (DEFAULT_WIDTH_OF_VIEW * 1.05) / (size_t)(subblockWidth + distance);
    /** Are QLabels enabled */
    const bool fQLabelsEnabled = true;

    QTimer *pollTimer;
    QTimer *pollTimer2;

    QPushButton *buttonPauseContinue = nullptr;

    // For adding text to block rectangles
    void AddText(uint256 hash, QPen pen, qreal x, qreal y, uint8_t blockType);

    void SubscribeToCoreSignals();
    void UnsubscribeFromCoreSignals();

    // Structures and functions for running simulations
    struct SimInfo
    {
        uint256 blockhash;
        uint32_t nDagViewerHeight = 0;
        std::vector<Link> vBlockPointsTo;
        bool fHaveBlock = false;
        bool fDoubleSpend = false;
        uint32_t nFork = 0;
        uint8_t blockType = LEGACY_BLOCK;
    };
    std::vector<SimInfo> vSimulation5;

    // Simulation maps based on block height and map of blocks with links
    std::map<uint32_t, std::map<uint256, std::vector<Link> > > mapSimulation1;
    std::map<uint32_t, std::map<uint256, std::vector<Link> > > mapSimulation2;

    // Remove the currently item highlighting from the scene.
    void RemoveHighlight();

    // Set pause or continue and notify the buttons so they change shown text
    void ShowPauseButton();
    void ShowContinueButton();

public:
    void SetPauseContinueButton(QPushButton *button) { buttonPauseContinue = button; }

private:
    // Create the data for the simulations
    uint8_t nRunSimulation = 0;
    void SetupSimulation1();
    void SetupSimulation2();
    void SetupSimulation5();

    // Save boost signals so we can unsubsribe the exact signal.
    boost::signals2::connection blockTipConn;
    boost::signals2::connection headerTipConn;
    boost::signals2::connection uncleConn;
    boost::signals2::connection resetConn;


private Q_SLOTS:
    void dagSimulation();
    void mousePressEvent(QMouseEvent *event);
    void hideEvent(QHideEvent *event);
    void sliderPress();

public Q_SLOTS:
    void ShowPauseContinueButtons();

    // Scale up and down the block view
    void ScaleUp();
    void ScaleDown();
};

#endif // DAGWIDGET_H
