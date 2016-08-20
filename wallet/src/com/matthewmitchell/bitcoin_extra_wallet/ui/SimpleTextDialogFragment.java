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
import android.text.Spannable;

import com.matthewmitchell.bitcoin_extra_wallet.Constants;
import com.matthewmitchell.bitcoin_extra_wallet.R;
import com.matthewmitchell.bitcoin_extra_wallet.util.GenericUtils;
import com.matthewmitchell.bitcoin_extra_wallet.util.Toast;
import com.matthewmitchell.bitcoin_extra_wallet.util.WholeStringBuilder;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.util.Locale;

/**
 * @author Matthew Mitchell
 */
public class SimpleTextDialogFragment extends DialogFragment
{
	private static final String FRAGMENT_TAG = SimpleTextDialogFragment.class.getName();

	private static final String KEY_MESSAGE = "message";
	private static final String KEY_TITLE = "title";

	public static void showWithMessage(final FragmentManager fm, CharSequence message, String title) {
		final DialogFragment newFragment = instance(message, title);
		newFragment.show(fm, FRAGMENT_TAG);
	}

	private static SimpleTextDialogFragment instance(CharSequence message, String title) {
		final SimpleTextDialogFragment fragment = new SimpleTextDialogFragment();

		final Bundle args = new Bundle();
		args.putCharSequence(KEY_MESSAGE, message);
		args.putString(KEY_TITLE, title);
		fragment.setArguments(args);

		return fragment;
	}

	@Override
	public Dialog onCreateDialog(final Bundle savedInstanceState)
	{
		final Bundle args = getArguments();
		final CharSequence message = args.getCharSequence(KEY_MESSAGE);
		final String title = args.getString(KEY_TITLE);

		final DialogBuilder dialog = new DialogBuilder(getActivity());
		dialog.setTitle(title);
		dialog.setMessage(message);
		dialog.setPositiveButton(WholeStringBuilder.bold(getString(R.string.button_dismiss)),
				new DialogInterface.OnClickListener()
				{
					@Override
					public void onClick(final DialogInterface dialog, final int which)
					{
						dialog.dismiss();
					}
				});

		return dialog.create();
	}

}
