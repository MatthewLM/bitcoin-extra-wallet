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

import java.io.File;
import java.util.Locale;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

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
import com.matthewmitchell.bitcoin_extra_wallet.util.GenericUtils;
import com.matthewmitchell.bitcoin_extra_wallet.util.Toast;
import com.matthewmitchell.bitcoin_extra_wallet.util.WholeStringBuilder;

import com.matthewmitchell.bitcoin_extra_wallet.R;

/**
 * @author Andreas Schildbach
 * @author Matthew Mitchell
 */
// Bitcoin Extra Modification: Reuse for transactions export.
public class ArchiveDialogFragment extends DialogFragment
{
	private static final String FRAGMENT_TAG = ArchiveDialogFragment.class.getName();

	private static final String KEY_FILE = "file";
	private static final String KEY_DIALOG_SUCCESS = "dialogSuccess";
	private static final String KEY_MAIL_SUBJECT = "mailSubject";
	private static final String KEY_MAIL_TEXT = "mailText";
	private static final String KEY_MIME_TYPE = "mimeType";
	private static final String KEY_CHOOSER_TITLE = "chooserTitle";
	private static final String KEY_FAIL_MESSAGE = "failMessage";
	private static final String KEY_LOG_TYPE = "logType";

	public static void show(final FragmentManager fm, final File file, final int dialogSuccess,
							final int mailSubject, final int mailText, final String mimeType,
							final int chooserTitle, final int failMessage, String logType)
	{
		final DialogFragment newFragment = instance(file, dialogSuccess, mailSubject, mailText,
				mimeType, chooserTitle, failMessage, logType);
		newFragment.show(fm, FRAGMENT_TAG);
	}

	private static ArchiveDialogFragment instance(
			final File file, final int dialogSuccess,
			final int mailSubject, final int mailText, final String mimeType,
			final int chooserTitle, final int failMessage, String logType)
	{
		final ArchiveDialogFragment fragment = new ArchiveDialogFragment();

		final Bundle args = new Bundle();
		args.putSerializable(KEY_FILE, file);
		args.putInt(KEY_DIALOG_SUCCESS, dialogSuccess);
		args.putInt(KEY_MAIL_SUBJECT, mailSubject);
		args.putInt(KEY_MAIL_TEXT, mailText);
		args.putString(KEY_MIME_TYPE, mimeType);
		args.putInt(KEY_CHOOSER_TITLE, chooserTitle);
		args.putInt(KEY_FAIL_MESSAGE, failMessage);
		args.putString(KEY_LOG_TYPE, logType);
		fragment.setArguments(args);

		return fragment;
	}

	private AbstractWalletActivity activity;

	private static final Logger log = LoggerFactory.getLogger(ArchiveBackupDialogFragment.class);

	@Override
	public void onAttach(final Activity activity)
	{
		super.onAttach(activity);

		this.activity = (AbstractWalletActivity) activity;
	}

	@Override
	public Dialog onCreateDialog(final Bundle savedInstanceState)
	{
		final Bundle args = getArguments();
		final File backupFile = (File) args.getSerializable(KEY_FILE);
		final int dialogSuccess = args.getInt(KEY_DIALOG_SUCCESS);
		final int mailSubject = args.getInt(KEY_MAIL_SUBJECT);
		final int mailText = args.getInt(KEY_MAIL_TEXT);
		final String mimeType = args.getString(KEY_MIME_TYPE);
		final int chooserTitle = args.getInt(KEY_CHOOSER_TITLE);
		final int failMessage = args.getInt(KEY_FAIL_MESSAGE);
		final String logType = args.getString(KEY_LOG_TYPE);

		final String path;
		final String backupPath = backupFile.getAbsolutePath();
		final String storagePath = Constants.Files.EXTERNAL_STORAGE_DIR.getAbsolutePath();
		if (backupPath.startsWith(storagePath))
			path = backupPath.substring(storagePath.length());
		else
			path = backupPath;

		final DialogBuilder dialog = new DialogBuilder(activity);
		dialog.setMessage(Html.fromHtml(getString(dialogSuccess, path)));
		dialog.setPositiveButton(WholeStringBuilder.bold(getString(R.string.export_keys_dialog_button_archive)),
				new DialogInterface.OnClickListener()
				{
					@Override
					public void onClick(final DialogInterface dialog, final int which)
					{
						final Intent intent = new Intent(Intent.ACTION_SEND);
						intent.putExtra(Intent.EXTRA_SUBJECT, getString(mailSubject));
						intent.putExtra(Intent.EXTRA_TEXT, GenericUtils.makeEmailText(getActivity(), getString(mailText)));
						intent.setType(mimeType);
						intent.putExtra(Intent.EXTRA_STREAM, Uri.fromFile(backupFile));

						try
						{
							startActivity(Intent.createChooser(intent, getString(chooserTitle)));
							log.info("invoked chooser for archiving {}", logType);
						}
						catch (final Exception x)
						{
							new Toast(activity).longToast(failMessage);
							log.error(String.format(Locale.US, "archiving %s failed", logType), x);
						}
					}
				});
		dialog.setNegativeButton(R.string.button_dismiss, null);

		return dialog.create();
	}

}
