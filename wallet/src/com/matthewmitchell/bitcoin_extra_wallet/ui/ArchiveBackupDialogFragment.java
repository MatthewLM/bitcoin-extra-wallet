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

import android.app.Activity;
import android.app.Dialog;
import android.app.DialogFragment;
import android.app.FragmentManager;
import android.content.DialogInterface;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.text.Html;

import com.matthewmitchell.bitcoin_extra_wallet.Constants;
import com.matthewmitchell.bitcoin_extra_wallet.R;
import com.matthewmitchell.bitcoin_extra_wallet.util.GenericUtils;
import com.matthewmitchell.bitcoin_extra_wallet.util.Toast;
import com.matthewmitchell.bitcoin_extra_wallet.util.WholeStringBuilder;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;

/**
 * @author Andreas Schildbach
 * @author Matthew Mitchell
 */
// Bitcoin Extra Modification: Reuse for transactions export.
public class ArchiveBackupDialogFragment {

	static final String LOG_TYPE = "wallet backup";

	public static void show(final FragmentManager fm, final File backupFile) {
		ArchiveDialogFragment.show(
				fm, backupFile,
				R.string.export_keys_dialog_success,
				R.string.export_keys_dialog_mail_subject,
				R.string.export_keys_dialog_mail_text,
				Constants.MIMETYPE_WALLET_BACKUP,
				R.string.export_keys_dialog_mail_intent_chooser,
				R.string.export_keys_dialog_mail_intent_failed,
				LOG_TYPE
		);
	}

}
