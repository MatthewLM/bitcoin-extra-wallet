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

import android.app.Dialog;
import android.app.DialogFragment;
import android.app.Fragment;
import android.app.FragmentManager;
import android.content.Context;
import android.content.DialogInterface;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ArrayAdapter;
import android.widget.TextView;

import com.matthewmitchell.bitcoin_extra_wallet.Constants;
import com.matthewmitchell.bitcoin_extra_wallet.R;
import com.matthewmitchell.bitcoin_extra_wallet.data.PaymentIntent;
import com.matthewmitchell.bitcoin_extra_wallet.ui.send.SendCoinsFragment;

import org.bitcoinj_extra.core.Coin;

/**
 * @author Matthew Mitchell
 */
public class DonateSelectionDialogFragment extends DialogFragment {

	private static class DonateOption {

		private final int title;
		private final int message;
        private final String address;
        private final int label;

		public DonateOption(int title, int message, String address, int label) {
			this.title = title;
			this.message = message;
            this.address = address;
            this.label = label;
		}

		public int getTitle() {
			return title;
		}

		public int getMessage() {
			return message;
		}

        public String getAddress() {
            return address;
        }

        public int getLabel() {
            return label;
        }
    }

	private static final String FRAGMENT_TAG = DonateSelectionDialogFragment.class.getName();
    private static final String KEY_AMOUNT = "amount";

	private static final DonateOption[] options = {
			new DonateOption(
                    R.string.donate_option_original_title,
                    R.string.donate_option_original_message,
                    Constants.DONATION_ORIGINAL,
                    R.string.wallet_donate_address_label_original
            ),
			new DonateOption(
                    R.string.donate_option_extra_title,
                    R.string.donate_option_extra_message,
                    Constants.DONATION_EXTRA,
                    R.string.wallet_donate_address_label_extra
            ),
	};

	public static void show(final FragmentManager fm, Fragment sendFragment, Coin amount) {
		final DialogFragment newFragment = new DonateSelectionDialogFragment();

        Bundle args = new Bundle();
        args.putSerializable(KEY_AMOUNT, amount);

        newFragment.setTargetFragment(sendFragment, 0);
        newFragment.setArguments(args);

		newFragment.show(fm, FRAGMENT_TAG);

	}

	@Override
	public Dialog onCreateDialog(final Bundle savedInstanceState) {
		
		final DialogBuilder dialog = new DialogBuilder(getActivity());
		dialog.setTitle(getActivity().getString(R.string.donation_dialog_title));

        dialog.setAdapter(
				new ArrayAdapter<DonateOption>(getActivity(), R.layout.donate_row_view, options) {

					@Override
					public View getView(int position, View view, ViewGroup parent) {

						if (view == null) {
							LayoutInflater inflater = (LayoutInflater) getContext().getSystemService(Context.LAYOUT_INFLATER_SERVICE);
							view = inflater.inflate(R.layout.donate_row_view, parent, false);
						}

						TextView title = (TextView) view.findViewById(R.id.donate_row_title);
						TextView message = (TextView) view.findViewById(R.id.donate_row_message);
						DonateOption option = getItem(position);

						title.setText(option.getTitle());
						message.setText(option.getMessage());

						return view;

					}

				},
				new DialogInterface.OnClickListener() {

					@Override
					public void onClick(DialogInterface dialog, int item) {

                        DonateOption option = options[item];
                        Bundle args = getArguments();
                        Coin amount = (Coin) args.getSerializable(KEY_AMOUNT);

                        PaymentIntent pi = PaymentIntent.from(option.getAddress(), getString(option.getLabel()), amount);
                        ((SendCoinsFragment) getTargetFragment()).updateStateFrom(pi);

						dialog.dismiss();

					}

				}
        );

		return dialog.create();

	}

}
