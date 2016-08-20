/*
 * Copyright 2011-2016 the original author or authors.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package com.matthewmitchell.bitcoin_extra_wallet.ui;

import android.content.AsyncTaskLoader;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.support.v4.content.LocalBroadcastManager;
import android.text.format.DateUtils;

import com.matthewmitchell.bitcoin_extra_wallet.Constants;
import com.matthewmitchell.bitcoin_extra_wallet.WalletApplication;
import com.matthewmitchell.bitcoin_extra_wallet.util.ThrottlingWalletChangeListener;

import org.bitcoinj_extra.core.Transaction;
import org.bitcoinj_extra.core.TransactionConfidence;
import org.bitcoinj_extra.utils.Threading;
import org.bitcoinj_extra.wallet.Wallet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.Date;
import java.util.List;
import java.util.Set;
import java.util.concurrent.RejectedExecutionException;

import javax.annotation.Nullable;

public class TransactionsLoader extends AsyncTaskLoader<List<Transaction>> {

    private static final Logger log = LoggerFactory.getLogger(TransactionsLoader.class);
    private static final long THROTTLE_MS = DateUtils.SECOND_IN_MILLIS;

    private LocalBroadcastManager broadcastManager;
    private final Wallet wallet;
    @Nullable
    private final WalletTransactionsFragment.Direction direction;

    TransactionsLoader(final Context context, final Wallet wallet, @Nullable final WalletTransactionsFragment.Direction direction) {
        super(context);

        this.broadcastManager = LocalBroadcastManager.getInstance(context.getApplicationContext());
        this.wallet = wallet;
        this.direction = direction;
    }

    public
    @Nullable
    WalletTransactionsFragment.Direction getDirection() {
        return direction;
    }

    @Override
    protected void onStartLoading() {
        super.onStartLoading();

        wallet.addCoinsReceivedEventListener(Threading.SAME_THREAD, transactionAddRemoveListener);
        wallet.addCoinsSentEventListener(Threading.SAME_THREAD, transactionAddRemoveListener);
        wallet.addChangeEventListener(Threading.SAME_THREAD, transactionAddRemoveListener);
        broadcastManager.registerReceiver(walletChangeReceiver, new IntentFilter(WalletApplication.ACTION_WALLET_REFERENCE_CHANGED));
        transactionAddRemoveListener.onReorganize(null); // trigger at least one reload

        safeForceLoad();
    }

    @Override
    protected void onStopLoading() {
        broadcastManager.unregisterReceiver(walletChangeReceiver);
        wallet.removeChangeEventListener(transactionAddRemoveListener);
        wallet.removeCoinsSentEventListener(transactionAddRemoveListener);
        wallet.removeCoinsReceivedEventListener(transactionAddRemoveListener);
        transactionAddRemoveListener.removeCallbacks();

        super.onStopLoading();
    }

    @Override
    protected void onReset() {
        broadcastManager.unregisterReceiver(walletChangeReceiver);
        wallet.removeChangeEventListener(transactionAddRemoveListener);
        wallet.removeCoinsSentEventListener(transactionAddRemoveListener);
        wallet.removeCoinsReceivedEventListener(transactionAddRemoveListener);
        transactionAddRemoveListener.removeCallbacks();

        super.onReset();
    }

    @Override
    public List<Transaction> loadInBackground() {
        org.bitcoinj_extra.core.Context.propagate(Constants.CONTEXT);

        final Set<Transaction> transactions = wallet.getTransactions(true);
        final List<Transaction> filteredTransactions = new ArrayList<Transaction>(transactions.size());

        for (final Transaction tx : transactions) {
            final boolean sent = tx.getValue(wallet).signum() < 0;
            final boolean isInternal = tx.getPurpose() == Transaction.Purpose.KEY_ROTATION;

            if ((direction == WalletTransactionsFragment.Direction.RECEIVED && !sent && !isInternal) || direction == null
                    || (direction == WalletTransactionsFragment.Direction.SENT && sent && !isInternal))
                filteredTransactions.add(tx);
        }

        Collections.sort(filteredTransactions, TRANSACTION_COMPARATOR);

        return filteredTransactions;
    }

    private final ThrottlingWalletChangeListener transactionAddRemoveListener = new ThrottlingWalletChangeListener(THROTTLE_MS, true, true, false) {
        @Override
        public void onThrottledWalletChanged() {
            safeForceLoad();
        }
    };

    private final BroadcastReceiver walletChangeReceiver = new BroadcastReceiver() {
        @Override
        public void onReceive(final Context context, final Intent intent) {
            safeForceLoad();
        }
    };

    private void safeForceLoad() {
        try {
            forceLoad();
        } catch (final RejectedExecutionException x) {
            log.info("rejected execution: " + TransactionsLoader.this.toString());
        }
    }

    private static final Comparator<Transaction> TRANSACTION_COMPARATOR = new Comparator<Transaction>() {
        @Override
        public int compare(final Transaction tx1, final Transaction tx2) {
            final boolean pending1 = tx1.getConfidence().getConfidenceType() == TransactionConfidence.ConfidenceType.PENDING;
            final boolean pending2 = tx2.getConfidence().getConfidenceType() == TransactionConfidence.ConfidenceType.PENDING;

            if (pending1 != pending2)
                return pending1 ? -1 : 1;

            final Date updateTime1 = tx1.getUpdateTime();
            final long time1 = updateTime1 != null ? updateTime1.getTime() : 0;
            final Date updateTime2 = tx2.getUpdateTime();
            final long time2 = updateTime2 != null ? updateTime2.getTime() : 0;

            if (time1 != time2)
                return time1 > time2 ? -1 : 1;

            return tx1.getHash().compareTo(tx2.getHash());
        }
    };
}
