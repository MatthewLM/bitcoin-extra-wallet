/*
 * Copyright 2015 the original author or authors.
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

import android.app.FragmentManager;

import com.matthewmitchell.bitcoin_extra_wallet.Constants;
import com.matthewmitchell.bitcoin_extra_wallet.R;

import java.io.File;

/**
 * @author Matthew Mitchell
 */
public class ArchiveTxExportDialogFragment {

	static final String LOG_TYPE = "transaction export";

	public static void show(final FragmentManager fm, final File file) {
		ArchiveDialogFragment.show(
				fm, file,
				R.string.export_transactions_dialog_success,
				R.string.export_transactions_mail_subject,
				R.string.export_transactions_mail_text,
				Constants.MIMETYPE_TX_EXPORT,
				R.string.export_transactions_mail_intent_chooser,
				R.string.export_transactions_mail_intent_failed,
				LOG_TYPE
		);
	}

}
