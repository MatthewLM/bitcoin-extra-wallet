/*
 * Copyright 2011-2015 the original author or authors.
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

package com.matthewmitchell.bitcoin_extra_wallet.ui.send;

import static com.google.common.base.Preconditions.checkNotNull;

import java.io.FileNotFoundException;
import java.io.InputStream;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.RejectedExecutionException;

import javax.annotation.Nullable;

import org.bitcoin.protocols.payments.Protos.Payment;
import org.bitcoinj_extra.core.Address;
import org.bitcoinj_extra.core.AddressFormatException;
import org.bitcoinj_extra.core.Coin;
import org.bitcoinj_extra.core.CoinDetails;
import org.bitcoinj_extra.core.InsufficientMoneyException;
import org.bitcoinj_extra.core.Monetary;
import org.bitcoinj_extra.core.Sha256Hash;
import org.bitcoinj_extra.core.Transaction;
import org.bitcoinj_extra.core.TransactionConfidence;
import org.bitcoinj_extra.core.TransactionConfidence.ConfidenceType;
import org.bitcoinj_extra.core.VerificationException;
import org.bitcoinj_extra.core.VersionedChecksummedBytes;
import org.bitcoinj_extra.protocols.payments.PaymentProtocol;
import org.bitcoinj_extra.shapeshift.AsyncHttpClient;
import org.bitcoinj_extra.shapeshift.ShapeShift;
import org.bitcoinj_extra.shapeshift.ShapeShiftCoin;
import org.bitcoinj_extra.shapeshift.ShapeShiftComm;
import org.bitcoinj_extra.shapeshift.ShapeShiftMonetary;
import org.bitcoinj_extra.uri.BitcoinURI;
import org.bitcoinj_extra.utils.MonetaryFormat;
import org.bitcoinj_extra.wallet.Wallet;
import org.bitcoinj_extra.wallet.KeyChain.KeyPurpose;
import org.bitcoinj_extra.wallet.SendRequest;
import org.bitcoinj_extra.wallet.Wallet.BalanceType;
import org.bitcoinj_extra.wallet.Wallet.CouldNotAdjustDownwards;
import org.bitcoinj_extra.wallet.Wallet.DustySendRequested;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.spongycastle.crypto.params.KeyParameter;

import com.google.common.base.Strings;
import com.matthewmitchell.bitcoin_extra_wallet.ui.DonateSelectionDialogFragment;
import com.netki.WalletNameResolver;
import com.netki.dns.DNSBootstrapService;
import com.netki.dnssec.DNSSECResolver;
import com.netki.exceptions.WalletNameCurrencyUnavailableException;
import com.netki.exceptions.WalletNameLookupException;
import com.netki.tlsa.CACertService;
import com.netki.tlsa.CertChainValidator;
import com.netki.tlsa.TLSAValidator;

import android.app.Activity;
import android.app.Fragment;
import android.app.FragmentManager;
import android.app.LoaderManager;
import android.app.LoaderManager.LoaderCallbacks;
import android.bluetooth.BluetoothAdapter;
import android.content.AsyncTaskLoader;
import android.content.ComponentName;
import android.content.ContentResolver;
import android.content.Context;
import android.content.CursorLoader;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.Loader;
import android.content.pm.PackageManager;
import android.database.ContentObserver;
import android.database.Cursor;
import android.database.MatrixCursor;
import android.database.MergeCursor;
import android.media.RingtoneManager;
import android.net.Uri;
import android.nfc.NdefMessage;
import android.nfc.NfcAdapter;
import android.os.Bundle;
import android.os.Handler;
import android.os.HandlerThread;
import android.os.Looper;
import android.os.Process;
import android.support.v7.widget.RecyclerView;
import android.text.Editable;
import android.text.TextWatcher;
import android.view.LayoutInflater;
import android.view.Menu;
import android.view.MenuInflater;
import android.view.MenuItem;
import android.view.View;
import android.view.View.OnClickListener;
import android.view.View.OnFocusChangeListener;
import android.view.ViewGroup;
import android.widget.AdapterView;
import android.widget.ArrayAdapter;
import android.widget.AutoCompleteTextView;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.CompoundButton;
import android.widget.CompoundButton.OnCheckedChangeListener;
import android.widget.CursorAdapter;
import android.widget.EditText;
import android.widget.FrameLayout;
import android.widget.LinearLayout;
import android.widget.Spinner;
import android.widget.TextView;
import com.matthewmitchell.bitcoin_extra_wallet.AddressBookProvider;
import com.matthewmitchell.bitcoin_extra_wallet.Configuration;
import com.matthewmitchell.bitcoin_extra_wallet.Constants;
import com.matthewmitchell.bitcoin_extra_wallet.ExchangeRatesProvider;
import com.matthewmitchell.bitcoin_extra_wallet.ExchangeRatesProvider.ExchangeRate;
import com.matthewmitchell.bitcoin_extra_wallet.WalletApplication;
import com.matthewmitchell.bitcoin_extra_wallet.data.PaymentIntent;
import com.matthewmitchell.bitcoin_extra_wallet.data.PaymentIntent.Standard;
import com.matthewmitchell.wallet.integration.android.BitcoinIntegration;
import com.matthewmitchell.bitcoin_extra_wallet.offline.DirectPaymentTask;
import com.matthewmitchell.bitcoin_extra_wallet.ui.AbstractBindServiceActivity;
import com.matthewmitchell.bitcoin_extra_wallet.ui.AddressAndLabel;
import com.matthewmitchell.bitcoin_extra_wallet.ui.CurrencyAmountView;
import com.matthewmitchell.bitcoin_extra_wallet.ui.CurrencyCalculatorLink;
import com.matthewmitchell.bitcoin_extra_wallet.ui.DialogBuilder;
import com.matthewmitchell.bitcoin_extra_wallet.ui.ExchangeRateLoader;
import com.matthewmitchell.bitcoin_extra_wallet.ui.InputParser.BinaryInputParser;
import com.matthewmitchell.bitcoin_extra_wallet.ui.InputParser.StreamInputParser;
import com.matthewmitchell.bitcoin_extra_wallet.ui.InputParser.StringInputParser;
import com.matthewmitchell.bitcoin_extra_wallet.ui.ProgressDialogFragment;
import com.matthewmitchell.bitcoin_extra_wallet.ui.ScanActivity;
import com.matthewmitchell.bitcoin_extra_wallet.ui.TransactionsAdapter;
import com.matthewmitchell.bitcoin_extra_wallet.util.Bluetooth;
import com.matthewmitchell.bitcoin_extra_wallet.util.Nfc;
import com.matthewmitchell.bitcoin_extra_wallet.util.WalletUtils;

import com.matthewmitchell.bitcoin_extra_wallet.R;

/**
 * @author Andreas Schildbach
 */
public final class SendCoinsFragment extends Fragment
{
	private AbstractBindServiceActivity activity;
	private WalletApplication application;
	private Configuration config;
	private Wallet wallet;
	private ContentResolver contentResolver;
	private LoaderManager loaderManager;
	private FragmentManager fragmentManager;
	@Nullable
	private BluetoothAdapter bluetoothAdapter;

	private final Handler handler = new Handler();
	private HandlerThread backgroundThread;
	private Handler backgroundHandler;

	private View payeeGroup;
	private TextView payeeNameView;
	private TextView payeeVerifiedByView;
	private AutoCompleteTextView receivingAddressView;
	private ReceivingAddressViewAdapter receivingAddressViewAdapter;
	private ReceivingAddressLoaderCallbacks receivingAddressLoaderCallbacks;
	private View receivingStaticView;
	private TextView receivingStaticAddressView;
	private TextView receivingStaticLabelView;
	private View amountGroup;
	private CurrencyCalculatorLink amountCalculatorLink;
	private CheckBox directPaymentEnableView;

	private TextView hintView;
	private TextView shapeShiftHintView;
	private TextView shapeShiftEstView;
	private TextView directPaymentMessageView;
	private FrameLayout sentTransactionView;
	private TransactionsAdapter sentTransactionAdapter;
	private RecyclerView.ViewHolder sentTransactionViewHolder;
	private View privateKeyPasswordViewGroup;
	private EditText privateKeyPasswordView;
	private View privateKeyBadPasswordView;
	private Button viewGo;
	private Button viewCancel;

	@Nullable
	private State state = null;

	private PaymentIntent paymentIntent = null;
	private FeeCategory feeCategory = FeeCategory.NORMAL;
	private AddressAndLabel validatedAddress = null;

	private Transaction sentTransaction = null;
	private Boolean directPaymentAck = null;

	private Transaction dryrunTransaction;
	private Exception dryrunException;

	// SHAPESHIFT

	private enum ShapeShiftStatus {
		NONE, FUTURE_UPDATE, UPDATING, OUTSIDE_LIMITS, PARSE_ERROR, CONNECTION_ERROR, OTHER_ERROR, TOO_SMALL
	}

	private LinearLayout shapeShiftTitles;
	private LinearLayout shapeShiftAmounts;
	private Spinner destCoinSpinner;
	private TextView shapeShiftForeignTitle;
	private CurrencyAmountView shapeShiftForeignAmountView;
	private CurrencyAmountView shapeShiftRateView;

	private ArrayAdapter destCoinSpinnerAdapter;

	private ShapeShiftCoin usingShapeShiftCoin;
	private boolean isExactForeignAmount;
	private Address depositAddress = null;
	private Address unusedSendAmountAddress = null;
	private ShapeShiftStatus shapeShiftStatus = ShapeShiftStatus.NONE;
	private String shapeShiftStatusText = "";
	private Coin limitMin;
	private Coin limitMax;
	private ShapeShiftComm activeShapeShiftComm = null;
	private Handler updateDelayHandler = new Handler(Looper.getMainLooper());
	private long lastSendAmountUpdate = 0;
	private long secondsToUpdate;
	private long futureUpdateTime;

	private final long SHAPESHIFT_ERROR_DELAY = 20000;
	private final long SHAPESHIFT_LIMIT_DELAY = 30000;
	private final long SHAPESHIFT_SHIFT_DELAY = 60 * 1000;
	private final long SHAPESHIFT_MIN_SEND_AMOUNT_DELAY = 5000;
	private final long SHAPESHIFT_SEND_AMOUNT_GAP = 5 * 60 * 1000;

	// END SHAPESHIFT

	private static final int ID_RATE_LOADER = 0;
	private static final int ID_RECEIVING_ADDRESS_BOOK_LOADER = 1;
	private static final int ID_RECEIVING_ADDRESS_NAME_LOADER = 2;

	private static final int REQUEST_CODE_SCAN = 0;
	private static final int REQUEST_CODE_ENABLE_BLUETOOTH_FOR_PAYMENT_REQUEST = 1;
	private static final int REQUEST_CODE_ENABLE_BLUETOOTH_FOR_DIRECT_PAYMENT = 2;

	private static final Logger log = LoggerFactory.getLogger(SendCoinsFragment.class);

	private enum State
	{
		REQUEST_PAYMENT_REQUEST, //
		INPUT, // asks for confirmation
		FINALISE_SHAPESHIFT,
		DECRYPTING, SIGNING, SENDING, SENT, FAILED // sending states
	}

	private final class ReceivingAddressListener implements OnFocusChangeListener, TextWatcher, AdapterView.OnItemClickListener
	{
		@Override
		public void onFocusChange(final View v, final boolean hasFocus)
		{
			if (!hasFocus)
			{
				validateReceivingAddress(false);
				updateView();
			}
		}

		@Override
		public void afterTextChanged(final Editable s)
		{
			if (s.length() > 0)
				validateReceivingAddress(true);
			else
				updateView();

			final Bundle args = new Bundle();
			args.putString(ReceivingAddressLoaderCallbacks.ARG_CONSTRAINT, s.toString());

			loaderManager.restartLoader(ID_RECEIVING_ADDRESS_BOOK_LOADER, args, receivingAddressLoaderCallbacks);
			if (config.getLookUpWalletNames())
				loaderManager.restartLoader(ID_RECEIVING_ADDRESS_NAME_LOADER, args, receivingAddressLoaderCallbacks);
		}

		@Override
		public void beforeTextChanged(final CharSequence s, final int start, final int count, final int after)
		{
		}

		@Override
		public void onTextChanged(final CharSequence s, final int start, final int before, final int count)
		{
		}

		@Override
		public void onItemClick(final AdapterView<?> parent, final View view, final int position, final long id)
		{
			final Cursor cursor = receivingAddressViewAdapter.getCursor();
			cursor.moveToPosition(position);
			final String address = cursor.getString(cursor.getColumnIndexOrThrow(AddressBookProvider.KEY_ADDRESS));
			final String label = cursor.getString(cursor.getColumnIndexOrThrow(AddressBookProvider.KEY_LABEL));
			try
			{
				validatedAddress = new AddressAndLabel(Constants.NETWORK_PARAMETERS, address, label);
				receivingAddressView.setText(null);
			}
			catch (final AddressFormatException x)
			{
				// swallow
			}
		}
	}

	private final ReceivingAddressListener receivingAddressListener = new ReceivingAddressListener();

	private final CurrencyAmountView.Listener amountsListener = new CurrencyAmountView.Listener()
	{
		@Override
		public void changed()
		{
            updateShapeShift(false);
			updateView();
			handler.post(dryrunRunnable);
		}

		@Override
		public void focusChanged(final boolean hasFocus)
		{
		}
	};

	private final TextWatcher privateKeyPasswordListener = new TextWatcher()
	{
		@Override
		public void onTextChanged(final CharSequence s, final int start, final int before, final int count)
		{
			privateKeyBadPasswordView.setVisibility(View.INVISIBLE);
			updateView();
		}

		@Override
		public void beforeTextChanged(final CharSequence s, final int start, final int count, final int after)
		{
		}

		@Override
		public void afterTextChanged(final Editable s)
		{
		}
	};

	private final ContentObserver contentObserver = new ContentObserver(handler)
	{
		@Override
		public void onChange(final boolean selfChange)
		{
			updateView();
		}
	};

	private final TransactionConfidence.Listener sentTransactionConfidenceListener = new TransactionConfidence.Listener()
	{
		@Override
		public void onConfidenceChanged(final TransactionConfidence confidence, final TransactionConfidence.Listener.ChangeReason reason)
		{
			activity.runOnUiThread(new Runnable()
			{
				@Override
				public void run()
				{
					if (!isResumed())
						return;

					final TransactionConfidence confidence = sentTransaction.getConfidence();
					final ConfidenceType confidenceType = confidence.getConfidenceType();
					final int numBroadcastPeers = confidence.numBroadcastPeers();

					if (state == State.SENDING)
					{
						if (confidenceType == ConfidenceType.DEAD)
						{
							setState(State.FAILED);
						}
						else if (numBroadcastPeers > 1 || confidenceType == ConfidenceType.BUILDING)
						{
							setState(State.SENT);

							// Auto-close the dialog after a short delay
							if (config.getSendCoinsAutoclose())
							{
								handler.postDelayed(new Runnable()
								{
									@Override
									public void run()
									{
										activity.finish();
									}
								}, 500);
							}
						}
					}

					if (reason == ChangeReason.SEEN_PEERS && confidenceType == ConfidenceType.PENDING)
					{
						// play sound effect
						final int soundResId = getResources().getIdentifier("send_coins_broadcast_" + numBroadcastPeers, "raw",
								activity.getPackageName());
						if (soundResId > 0)
							RingtoneManager.getRingtone(activity, Uri.parse("android.resource://" + activity.getPackageName() + "/" + soundResId))
									.play();
					}

					updateView();
				}
			});
		}
	};

	private final LoaderCallbacks<Cursor> rateLoaderCallbacks = new LoaderManager.LoaderCallbacks<Cursor>()
	{
		@Override
		public Loader<Cursor> onCreateLoader(final int id, final Bundle args)
		{
			return new ExchangeRateLoader(activity, config);
		}

		@Override
		public void onLoadFinished(final Loader<Cursor> loader, final Cursor data)
		{
			if (data != null && data.getCount() > 0)
			{
				data.moveToFirst();
				final ExchangeRate exchangeRate = ExchangeRatesProvider.getExchangeRate(data);

				if (state == null || state.compareTo(State.INPUT) <= 0)
					amountCalculatorLink.setExchangeRate(exchangeRate.rate);
			}
		}

		@Override
		public void onLoaderReset(final Loader<Cursor> loader)
		{
		}
	};

	private static class ReceivingAddressLoaderCallbacks implements LoaderManager.LoaderCallbacks<Cursor>
	{
		private final static String ARG_CONSTRAINT = "constraint";

		private final Context context;
		private final CursorAdapter targetAdapter;
		private Cursor receivingAddressBookCursor, receivingAddressNameCursor;

		public ReceivingAddressLoaderCallbacks(final Context context, final CursorAdapter targetAdapter)
		{
			this.context = checkNotNull(context);
			this.targetAdapter = checkNotNull(targetAdapter);
		}

		@Override
		public Loader<Cursor> onCreateLoader(final int id, final Bundle args)
		{
			final String constraint = Strings.nullToEmpty(args != null ? args.getString(ARG_CONSTRAINT) : null);

			if (id == ID_RECEIVING_ADDRESS_BOOK_LOADER)
				return new CursorLoader(context, AddressBookProvider.contentUri(context.getPackageName()), null, AddressBookProvider.SELECTION_QUERY,
						new String[] { constraint }, null);
			else if (id == ID_RECEIVING_ADDRESS_NAME_LOADER)
				return new ReceivingAddressNameLoader(context, constraint);
			else
				throw new IllegalArgumentException();
		}

		@Override
		public void onLoadFinished(final Loader<Cursor> loader, Cursor data)
		{
			if (data.getCount() == 0)
				data = null;
			if (loader instanceof CursorLoader)
				receivingAddressBookCursor = data;
			else
				receivingAddressNameCursor = data;
			swapTargetCursor();
		}

		@Override
		public void onLoaderReset(final Loader<Cursor> loader)
		{
			if (loader instanceof CursorLoader)
				receivingAddressBookCursor = null;
			else
				receivingAddressNameCursor = null;
			swapTargetCursor();
		}

		private void swapTargetCursor()
		{
			if (receivingAddressBookCursor == null && receivingAddressNameCursor == null)
				targetAdapter.swapCursor(null);
			else if (receivingAddressBookCursor != null && receivingAddressNameCursor == null)
				targetAdapter.swapCursor(receivingAddressBookCursor);
			else if (receivingAddressBookCursor == null && receivingAddressNameCursor != null)
				targetAdapter.swapCursor(receivingAddressNameCursor);
			else
				targetAdapter.swapCursor(new MergeCursor(new Cursor[] { receivingAddressBookCursor, receivingAddressNameCursor }));
		}
	}

	private static class ReceivingAddressNameLoader extends AsyncTaskLoader<Cursor>
	{
		private String constraint;

		public ReceivingAddressNameLoader(final Context context, final String constraint)
		{
			super(context);
			this.constraint = constraint;
		}

		@Override
		protected void onStartLoading()
		{
			super.onStartLoading();
			safeForceLoad();
		}

		@Override
		public Cursor loadInBackground()
		{
			final MatrixCursor cursor = new MatrixCursor(
					new String[] { AddressBookProvider.KEY_ROWID, AddressBookProvider.KEY_LABEL, AddressBookProvider.KEY_ADDRESS }, 1);

			if (constraint.indexOf('.') >= 0 || constraint.indexOf('@') >= 0)
			{
				try
				{
					final WalletNameResolver resolver = new WalletNameResolver(new DNSSECResolver(new DNSBootstrapService()),
							new TLSAValidator(new DNSSECResolver(new DNSBootstrapService()), CACertService.getInstance(), new CertChainValidator()));
					final BitcoinURI resolvedUri = resolver.resolve(constraint, Constants.WALLET_NAME_CURRENCY_CODE, true);
					if (resolvedUri != null)
					{
						final Address resolvedAddress = resolvedUri.getAddress();
						if (resolvedAddress != null && resolvedAddress.getCoinDetails().equals(Constants.NETWORK_PARAMETERS))
						{
							final String resolvedLabel = Strings.emptyToNull(resolvedUri.getLabel());
							cursor.addRow(new Object[] { -1, resolvedLabel != null ? resolvedLabel : constraint, resolvedAddress.toString() });
							log.info("looked up wallet name: " + resolvedUri);
						}
					}
				}
				catch (final WalletNameCurrencyUnavailableException x)
				{
					// swallow
				}
				catch (final WalletNameLookupException x)
				{
					log.info("error looking up wallet name '" + constraint + "': " + x.getMessage());
				}
				catch (final Exception x)
				{
					log.info("error looking up wallet name", x);
				}
			}

			return cursor;
		}

		private void safeForceLoad()
		{
			try
			{
				forceLoad();
			}
			catch (final RejectedExecutionException x)
			{
				log.info("rejected execution: " + ReceivingAddressNameLoader.this.toString());
			}
		}
	}

	private final class ReceivingAddressViewAdapter extends CursorAdapter
	{
		public ReceivingAddressViewAdapter(final Context context)
		{
			super(context, null, false);
		}

		@Override
		public View newView(final Context context, final Cursor cursor, final ViewGroup parent)
		{
			final LayoutInflater inflater = LayoutInflater.from(context);
			return inflater.inflate(R.layout.address_book_row, parent, false);
		}

		@Override
		public void bindView(final View view, final Context context, final Cursor cursor)
		{
			final String label = cursor.getString(cursor.getColumnIndexOrThrow(AddressBookProvider.KEY_LABEL));
			final String address = cursor.getString(cursor.getColumnIndexOrThrow(AddressBookProvider.KEY_ADDRESS));

			final ViewGroup viewGroup = (ViewGroup) view;
			final TextView labelView = (TextView) viewGroup.findViewById(R.id.address_book_row_label);
			labelView.setText(label);
			final TextView addressView = (TextView) viewGroup.findViewById(R.id.address_book_row_address);
			addressView.setText(WalletUtils.formatHash(address, Constants.ADDRESS_FORMAT_GROUP_SIZE, Constants.ADDRESS_FORMAT_LINE_SIZE));
		}

		@Override
		public CharSequence convertToString(final Cursor cursor)
		{
			return cursor.getString(cursor.getColumnIndexOrThrow(AddressBookProvider.KEY_ADDRESS));
		}
	}

	private final DialogInterface.OnClickListener activityDismissListener = new DialogInterface.OnClickListener()
	{
		@Override
		public void onClick(final DialogInterface dialog, final int which)
		{
			activity.finish();
		}
	};

	@Override
	public void onAttach(final Activity activity)
	{
		super.onAttach(activity);

		this.activity = (AbstractBindServiceActivity) activity;
		this.application = (WalletApplication) activity.getApplication();
		this.config = application.getConfiguration();
		this.wallet = application.getWallet();
		this.contentResolver = activity.getContentResolver();
		this.loaderManager = getLoaderManager();
		this.fragmentManager = getFragmentManager();
	}

	@Override
	public void onCreate(final Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        setRetainInstance(true);
        setHasOptionsMenu(true);

        bluetoothAdapter = BluetoothAdapter.getDefaultAdapter();

        backgroundThread = new HandlerThread("backgroundThread", Process.THREAD_PRIORITY_BACKGROUND);
        backgroundThread.start();
        backgroundHandler = new Handler(backgroundThread.getLooper());

    }

    @Override
    public void onActivityCreated(final Bundle savedInstanceState) {

        // As the fragment is retained, restore instance state here, because onCreate will not
        // be called.

        super.onActivityCreated(savedInstanceState);

		if (savedInstanceState != null)
		{
			restoreInstanceState(savedInstanceState);
		}
		else
		{
			final Intent intent = activity.getIntent();
			final String action = intent.getAction();
			final Uri intentUri = intent.getData();
			final String scheme = intentUri != null ? intentUri.getScheme() : null;
			final String mimeType = intent.getType();

			if ((Intent.ACTION_VIEW.equals(action) || NfcAdapter.ACTION_NDEF_DISCOVERED.equals(action)) && intentUri != null
					&& ("bitcoin".equals(scheme) || ShapeShift.getCoin(scheme) != null))
			{
				initStateFromBitcoinUri(intentUri);
			}
			else if ((NfcAdapter.ACTION_NDEF_DISCOVERED.equals(action)) && PaymentProtocol.MIMETYPE_PAYMENTREQUEST.equals(mimeType))
			{
				final NdefMessage ndefMessage = (NdefMessage) intent.getParcelableArrayExtra(NfcAdapter.EXTRA_NDEF_MESSAGES)[0];
				final byte[] ndefMessagePayload = Nfc.extractMimePayload(PaymentProtocol.MIMETYPE_PAYMENTREQUEST, ndefMessage);
				initStateFromPaymentRequest(mimeType, ndefMessagePayload);
			}
			else if ((Intent.ACTION_VIEW.equals(action)) && PaymentProtocol.MIMETYPE_PAYMENTREQUEST.equals(mimeType))
			{
				final byte[] paymentRequest = BitcoinIntegration.paymentRequestFromIntent(intent);

				if (intentUri != null)
					initStateFromIntentUri(mimeType, intentUri);
				else if (paymentRequest != null)
					initStateFromPaymentRequest(mimeType, paymentRequest);
				else
					throw new IllegalArgumentException();
			}
			else if (intent.hasExtra(SendCoinsActivity.INTENT_EXTRA_PAYMENT_INTENT))
			{
				initStateFromIntentExtras(intent.getExtras());
			}
			else
			{
				updateStateFrom(PaymentIntent.blank());
			}

            if (intent.hasExtra(SendCoinsActivity.INTENT_EXTRA_DONATE))
                // Provide donation options
                DonateSelectionDialogFragment.show(getFragmentManager(), this, (Coin) intent.getSerializableExtra(SendCoinsActivity.INTENT_EXTRA_DONATE));

		}
	}

	@Override
	public View onCreateView(final LayoutInflater inflater, final ViewGroup container, final Bundle savedInstanceState)
	{
		final View view = inflater.inflate(R.layout.send_coins_fragment, container);

		payeeGroup = view.findViewById(R.id.send_coins_payee_group);

		payeeNameView = (TextView) view.findViewById(R.id.send_coins_payee_name);
		payeeVerifiedByView = (TextView) view.findViewById(R.id.send_coins_payee_verified_by);

        shapeShiftTitles = (LinearLayout) view.findViewById(R.id.send_coins_shapeshift_titles);
        shapeShiftAmounts = (LinearLayout) view.findViewById(R.id.send_coins_shapeshift_amounts);
        destCoinSpinner = (Spinner) view.findViewById(R.id.send_coins_shapeshift_dest_coin_spinner);
        shapeShiftForeignTitle = (TextView) view.findViewById(R.id.send_coins_fragment_shapeshift_foreign_label);
        shapeShiftForeignAmountView = (CurrencyAmountView) view.findViewById(R.id.send_coins_shapeshift_foreign);
        shapeShiftRateView = (CurrencyAmountView) view.findViewById(R.id.send_coins_shapeshift_rate);

        destCoinSpinnerAdapter = new ArrayAdapter<CoinDetails>(getActivity(), android.R.layout.simple_spinner_item);
        destCoinSpinnerAdapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
        destCoinSpinner.setAdapter(destCoinSpinnerAdapter);

        destCoinSpinner.setOnItemSelectedListener(new AdapterView.OnItemSelectedListener() {

            @Override
            public void onItemSelected(AdapterView<?> parent, View view, int position, long id) {

                CoinDetails network = (CoinDetails) parent.getItemAtPosition(position);

                if (network.isShapeShift()) {
                    // Only set shapeshift again if network changed
                    if (network != usingShapeShiftCoin)
                        setShapeShift((ShapeShiftCoin) network, isExactForeignAmount, null);
                }else
                    usingShapeShiftCoin = null;

                updateView();

            }

            @Override
            public void onNothingSelected(AdapterView<?> parent) {

            }

        });

        shapeShiftForeignAmountView.setListener(new CurrencyAmountView.Listener() {

            @Override
            public void changed() {

                updateShapeShift(true);

            }

            @Override
            public void focusChanged(boolean hasFocus) {

            }

        });

		receivingAddressView = (AutoCompleteTextView) view.findViewById(R.id.send_coins_receiving_address);
		receivingAddressViewAdapter = new ReceivingAddressViewAdapter(activity);
		receivingAddressLoaderCallbacks = new ReceivingAddressLoaderCallbacks(activity, receivingAddressViewAdapter);
		receivingAddressView.setAdapter(receivingAddressViewAdapter);
		receivingAddressView.setOnFocusChangeListener(receivingAddressListener);
		receivingAddressView.addTextChangedListener(receivingAddressListener);
		receivingAddressView.setOnItemClickListener(receivingAddressListener);

		receivingStaticView = view.findViewById(R.id.send_coins_receiving_static);
		receivingStaticAddressView = (TextView) view.findViewById(R.id.send_coins_receiving_static_address);
		receivingStaticLabelView = (TextView) view.findViewById(R.id.send_coins_receiving_static_label);

		amountGroup = view.findViewById(R.id.send_coins_amount_group);

		final CurrencyAmountView btcAmountView = (CurrencyAmountView) view.findViewById(R.id.send_coins_amount_btc);

        for (CurrencyAmountView v : new CurrencyAmountView []{btcAmountView, shapeShiftRateView}) {
            v.setCurrencySymbol(config.getFormat().code());
            v.setInputFormat(config.getMaxPrecisionFormat());
            v.setHintFormat(config.getFormat());
        }

		final CurrencyAmountView localAmountView = (CurrencyAmountView) view.findViewById(R.id.send_coins_amount_local);
		localAmountView.setInputFormat(Constants.LOCAL_FORMAT);
		localAmountView.setHintFormat(Constants.LOCAL_FORMAT);
		amountCalculatorLink = new CurrencyCalculatorLink(btcAmountView, localAmountView);
		amountCalculatorLink.setExchangeDirection(config.getLastExchangeDirection());

		directPaymentEnableView = (CheckBox) view.findViewById(R.id.send_coins_direct_payment_enable);
		directPaymentEnableView.setOnCheckedChangeListener(new OnCheckedChangeListener()
		{
			@Override
			public void onCheckedChanged(final CompoundButton buttonView, final boolean isChecked)
			{
				if (paymentIntent.isBluetoothPaymentUrl() && isChecked && !bluetoothAdapter.isEnabled())
				{
					// ask for permission to enable bluetooth
					startActivityForResult(new Intent(BluetoothAdapter.ACTION_REQUEST_ENABLE), REQUEST_CODE_ENABLE_BLUETOOTH_FOR_DIRECT_PAYMENT);
				}
			}
		});

		hintView = (TextView) view.findViewById(R.id.send_coins_hint);
        shapeShiftHintView = (TextView) view.findViewById(R.id.send_coins_shapeshift_hint);
        shapeShiftEstView = (TextView) view.findViewById(R.id.send_coins_shapeshift_est);
        shapeShiftEstView.setText(R.string.send_coins_fragment_hint_shapeshift_estimated);

        directPaymentMessageView = (TextView) view.findViewById(R.id.send_coins_direct_payment_message);

		sentTransactionView = (FrameLayout) view.findViewById(R.id.send_coins_sent_transaction);
		sentTransactionAdapter = new TransactionsAdapter(activity, wallet, false, application.maxConnectedPeers(), null);
		sentTransactionViewHolder = sentTransactionAdapter.createTransactionViewHolder(sentTransactionView);
		sentTransactionView.addView(sentTransactionViewHolder.itemView, new FrameLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT,
				ViewGroup.LayoutParams.WRAP_CONTENT));

		privateKeyPasswordViewGroup = view.findViewById(R.id.send_coins_private_key_password_group);
		privateKeyPasswordView = (EditText) view.findViewById(R.id.send_coins_private_key_password);
		privateKeyBadPasswordView = view.findViewById(R.id.send_coins_private_key_bad_password);

		viewGo = (Button) view.findViewById(R.id.send_coins_go);
		viewGo.setOnClickListener(new OnClickListener()
		{
			@Override
			public void onClick(final View v)
			{
				validateReceivingAddress(false);

				if (everythingPlausible())
					handleGo();
				else
					requestFocusFirst();

				updateView();
			}
		});

		viewCancel = (Button) view.findViewById(R.id.send_coins_cancel);
		viewCancel.setOnClickListener(new OnClickListener()
		{
			@Override
			public void onClick(final View v)
			{
				handleCancel();
			}
		});

        return view;
	}

	@Override
	public void onDestroyView()
	{
		super.onDestroyView();

		config.setLastExchangeDirection(amountCalculatorLink.getExchangeDirection());
	}

	@Override
	public void onResume()
	{
		super.onResume();

		contentResolver.registerContentObserver(AddressBookProvider.contentUri(activity.getPackageName()), true, contentObserver);

		amountCalculatorLink.setListener(amountsListener);
		privateKeyPasswordView.addTextChangedListener(privateKeyPasswordListener);

		loaderManager.initLoader(ID_RATE_LOADER, null, rateLoaderCallbacks);
		loaderManager.initLoader(ID_RECEIVING_ADDRESS_BOOK_LOADER, null, receivingAddressLoaderCallbacks);
		loaderManager.initLoader(ID_RECEIVING_ADDRESS_NAME_LOADER, null, receivingAddressLoaderCallbacks);

		updateView();
		handler.post(dryrunRunnable);
	}

	@Override
	public void onPause()
	{
		loaderManager.destroyLoader(ID_RECEIVING_ADDRESS_NAME_LOADER);
		loaderManager.destroyLoader(ID_RECEIVING_ADDRESS_BOOK_LOADER);
		loaderManager.destroyLoader(ID_RATE_LOADER);

		privateKeyPasswordView.removeTextChangedListener(privateKeyPasswordListener);
		amountCalculatorLink.setListener(null);

		contentResolver.unregisterContentObserver(contentObserver);

		super.onPause();
	}

	@Override
	public void onDetach()
	{
		handler.removeCallbacksAndMessages(null);
        updateDelayHandler.removeCallbacksAndMessages(null);

		super.onDetach();
	}

	@Override
	public void onDestroy()
	{
		backgroundThread.getLooper().quit();

		if (sentTransaction != null)
			sentTransaction.getConfidence().removeEventListener(sentTransactionConfidenceListener);

		super.onDestroy();
	}

	@Override
	public void onSaveInstanceState(final Bundle outState)
	{
		super.onSaveInstanceState(outState);

		saveInstanceState(outState);
	}

	private void saveInstanceState(final Bundle outState)
	{
		outState.putSerializable("state", state);

		outState.putParcelable("payment_intent", paymentIntent);
		outState.putSerializable("fee_category", feeCategory);
		outState.putSerializable("exchange_rate", amountCalculatorLink.getExchangeRate());

		if (validatedAddress != null)
			outState.putParcelable("validated_address", validatedAddress);
		if (sentTransaction != null)
			outState.putSerializable("sent_transaction_hash", sentTransaction.getHash());
		if (directPaymentAck != null)
			outState.putBoolean("direct_payment_ack", directPaymentAck);

        if (usingShapeShiftCoin != null) {
            outState.putString("shapeshift_coin", usingShapeShiftCoin.getId());
            outState.putBoolean("exact_foreign_amount", isExactForeignAmount);
            outState.putSerializable("shapeshift_status", shapeShiftStatus);
            outState.putSerializable("shapeshift_foreign_amount", shapeShiftForeignAmountView.getAmount());
            outState.putLong("shapeshift_last_update", lastSendAmountUpdate);
            outState.putLong("shapeshift_update_time", futureUpdateTime);
        }

	}

	private void restoreInstanceState(final Bundle savedInstanceState)
	{
		state = (State) savedInstanceState.getSerializable("state");

		paymentIntent = (PaymentIntent) savedInstanceState.getParcelable("payment_intent");
		feeCategory = (FeeCategory) savedInstanceState.getSerializable("fee_category");
        amountCalculatorLink.setExchangeRate(
                (org.bitcoinj_extra.utils.ExchangeRate) savedInstanceState.getSerializable("exchange_rate")
        );
		validatedAddress = savedInstanceState.getParcelable("validated_address");

        if (paymentIntent.networks != null)
            destCoinSpinnerAdapter.addAll(paymentIntent.networks);
        else if (validatedAddress != null)
            destCoinSpinnerAdapter.addAll(validatedAddress.address.getCoinDetails());

		if (savedInstanceState.containsKey("sent_transaction_hash"))
		{
			sentTransaction = wallet.getTransaction((Sha256Hash) savedInstanceState.getSerializable("sent_transaction_hash"));
			sentTransaction.getConfidence().addEventListener(sentTransactionConfidenceListener);
		}
		if (savedInstanceState.containsKey("direct_payment_ack"))
			directPaymentAck = savedInstanceState.getBoolean("direct_payment_ack");

        if (savedInstanceState.containsKey("shapeshift_coin")) {

            shapeShiftStatus = (ShapeShiftStatus) savedInstanceState.getSerializable("shapeshift_status");
            lastSendAmountUpdate = savedInstanceState.getLong("shapeshift_last_update");
            isExactForeignAmount = savedInstanceState.getBoolean("exact_foreign_amount");
            futureUpdateTime = savedInstanceState.getLong("shapeshift_update_time");

            setShapeShiftNoUpdate(ShapeShift.getCoin(savedInstanceState.getString("shapeshift_coin")),
                    (Monetary) savedInstanceState.getSerializable("shapeshift_foreign_amount"));

            // As the amounts get reset after this function run it in a Handler

            handler.post(new Runnable() {

                @Override
                public void run() {
                    if (shapeShiftStatus == ShapeShiftStatus.FUTURE_UPDATE)
                        futureUpdate(futureUpdateTime - System.currentTimeMillis());
                    else
                        updateShapeShift(isExactForeignAmount);
                }

            });

        }

	}

	@Override
	public void onActivityResult(final int requestCode, final int resultCode, final Intent intent)
	{
		handler.post(new Runnable()
		{
			@Override
			public void run()
			{
				onActivityResultResumed(requestCode, resultCode, intent);
			}
		});
	}

	private void onActivityResultResumed(final int requestCode, final int resultCode, final Intent intent)
	{
		if (requestCode == REQUEST_CODE_SCAN)
		{
			if (resultCode == Activity.RESULT_OK)
			{
				final String input = intent.getStringExtra(ScanActivity.INTENT_EXTRA_RESULT);

				new StringInputParser(input)
				{
					@Override
					protected void handlePaymentIntent(final PaymentIntent paymentIntent)
					{
						setState(null);

						updateStateFrom(paymentIntent);
					}

					@Override
					protected void handleDirectTransaction(final Transaction transaction) throws VerificationException
					{
						cannotClassify(input);
					}

					@Override
					protected void error(final int messageResId, final Object... messageArgs)
					{
						dialog(activity, null, R.string.button_scan, messageResId, messageArgs);
					}
				}.parse();
			}
		}
		else if (requestCode == REQUEST_CODE_ENABLE_BLUETOOTH_FOR_PAYMENT_REQUEST)
		{
			if (paymentIntent.isBluetoothPaymentRequestUrl() && usingShapeShiftCoin == null)
				requestPaymentRequest();
		}
		else if (requestCode == REQUEST_CODE_ENABLE_BLUETOOTH_FOR_DIRECT_PAYMENT)
		{
			if (paymentIntent.isBluetoothPaymentUrl() && usingShapeShiftCoin == null)
				directPaymentEnableView.setChecked(resultCode == Activity.RESULT_OK);
		}
	}

	@Override
	public void onCreateOptionsMenu(final Menu menu, final MenuInflater inflater)
	{
		inflater.inflate(R.menu.send_coins_fragment_options, menu);

		super.onCreateOptionsMenu(menu, inflater);
	}

	@Override
	public void onPrepareOptionsMenu(final Menu menu)
	{
		final MenuItem scanAction = menu.findItem(R.id.send_coins_options_scan);
		final PackageManager pm = activity.getPackageManager();
		scanAction.setVisible(pm.hasSystemFeature(PackageManager.FEATURE_CAMERA) || pm.hasSystemFeature(PackageManager.FEATURE_CAMERA_FRONT));
		scanAction.setEnabled(state == State.INPUT);

		final MenuItem emptyAction = menu.findItem(R.id.send_coins_options_empty);
		emptyAction.setEnabled(state == State.INPUT && paymentIntent.mayEditAmount());

		final MenuItem feeCategoryAction = menu.findItem(R.id.send_coins_options_fee_category);
		feeCategoryAction.setEnabled(state == State.INPUT);
		if (feeCategory == FeeCategory.ECONOMIC)
			menu.findItem(R.id.send_coins_options_fee_category_economic).setChecked(true);
		else if (feeCategory == FeeCategory.NORMAL)
			menu.findItem(R.id.send_coins_options_fee_category_normal).setChecked(true);
		else if (feeCategory == FeeCategory.PRIORITY)
			menu.findItem(R.id.send_coins_options_fee_category_priority).setChecked(true);

		super.onPrepareOptionsMenu(menu);
	}

	@Override
	public boolean onOptionsItemSelected(final MenuItem item)
	{
		switch (item.getItemId())
		{
			case R.id.send_coins_options_scan:
				handleScan();
				return true;

			case R.id.send_coins_options_fee_category_economic:
				handleFeeCategory(FeeCategory.ECONOMIC);
				return true;
			case R.id.send_coins_options_fee_category_normal:
				handleFeeCategory(FeeCategory.NORMAL);
				return true;
			case R.id.send_coins_options_fee_category_priority:
				handleFeeCategory(FeeCategory.PRIORITY);
				return true;

			case R.id.send_coins_options_empty:
				handleEmpty();
				return true;
		}

		return super.onOptionsItemSelected(item);
	}

    private Address getAddress() {
        if (paymentIntent.hasAddress())
            return paymentIntent.getAddress();
        if (validatedAddress != null)
            return validatedAddress.address;
        return null;
    }

    private boolean maybeUpdateShapeShift() {

        if (usingShapeShiftCoin == null)
            return true;

        if (activeShapeShiftComm != null && activeShapeShiftComm.shouldStop()) {
            activeShapeShiftComm = null;
            updateShapeShift(isExactForeignAmount);
            return true;
        }

        return false;

    }

    private void futureUpdate(long delay) {

        activeShapeShiftComm = null;
        if (shapeShiftStatus == ShapeShiftStatus.NONE)
            shapeShiftStatus = ShapeShiftStatus.FUTURE_UPDATE;

        updateDelayHandler.removeCallbacksAndMessages(null);

        futureUpdateTime = System.currentTimeMillis() + delay;

        final Runnable timerRunnable = new Runnable() {

            @Override
            public void run() {

                if (state != State.INPUT)
                    return;

                long now = System.currentTimeMillis();
                long remaining = futureUpdateTime - now;

                if (remaining <= 0) {
                    updateShapeShift(isExactForeignAmount);
                    return;
                }

                // Split minutes, seconds and milliseconds

                long milipart = remaining % 1000;
                remaining /= 1000;
                secondsToUpdate = remaining;
                long secondPart = remaining % 60;
                remaining /= 60;
                long minutePart = remaining;

                // Update UI
                updateView();

                // Get time delay of the next update

                long updateDelay = milipart + 1; // Add one to absolutely ensure it falls to the next time period

                if (minutePart == 1)
                    // Get to seconds
                    updateDelay += secondPart * 1000;
                else if (minutePart > 1)
                    // Get to the next half minute to round to the nearest minute
                    updateDelay += (secondPart >= 30 ? secondPart - 30 : secondPart + 30) * 1000;

                updateDelayHandler.postDelayed(this, updateDelay);
            }


        };

        timerRunnable.run();

    }

    private void handleShapeShiftError(final int networkCode, final String text) {
        if (networkCode == AsyncHttpClient.CONNECTION_ERROR)
            shapeShiftStatus = ShapeShiftStatus.CONNECTION_ERROR;
        else if (networkCode == AsyncHttpClient.PARSE_ERROR)
            shapeShiftStatus = ShapeShiftStatus.PARSE_ERROR;
        else {
            shapeShiftStatus = ShapeShiftStatus.OTHER_ERROR;
            shapeShiftStatusText = text;
        }
    }

    class ShapeShiftCallbacks extends ShapeShiftComm.Callbacks {

        @Override
        public void networkError(final int networkCode, final String text) {

            SendCoinsFragment.this.activity.runOnUiThread(new Runnable() {

                @Override
                public void run() {

                    if (maybeUpdateShapeShift())
                        return;

                    handler.post(dryrunRunnable);
                    handleShapeShiftError(networkCode, text);
                    futureUpdate(SHAPESHIFT_ERROR_DELAY);

                }

            });

        }

    }

    private void shapeShiftWaitForAmount() {
        shapeShiftRateView.setAmount(Coin.ZERO, false);
        activeShapeShiftComm = null;
        dryrunTransaction = null;
        shapeShiftStatus = ShapeShiftStatus.NONE;
        updateView();
    }

    private void updateShapeShift(boolean isExactForeignAmountLocal) {
        // Make the necessary shapeshift calls

        if (usingShapeShiftCoin == null || state != State.INPUT)
            return;

        updateDelayHandler.removeCallbacksAndMessages(null);
        isExactForeignAmount = isExactForeignAmountLocal;

        if (activeShapeShiftComm != null) {
            activeShapeShiftComm.stop();
            return;
        }

        final ShapeShiftComm shapeShiftComm = new ShapeShiftComm();
        activeShapeShiftComm = shapeShiftComm;
        depositAddress = null;

        if (isExactForeignAmount) {

            final ShapeShiftMonetary amount = (ShapeShiftMonetary) shapeShiftForeignAmountView.getAmount();

            if (amount == null) {
                amountCalculatorLink.setBtcAmount(null);
                shapeShiftWaitForAmount();
                return;
            }

            long timeRemaining = SHAPESHIFT_MIN_SEND_AMOUNT_DELAY - (System.currentTimeMillis() - lastSendAmountUpdate);

            if (timeRemaining > 0) {
                // Do not update now
                futureUpdate(timeRemaining);
                return;
            }

            shapeShiftComm.setCallbacks(new ShapeShiftCallbacks() {

                @Override
                public void sendAmountResponse(final Address deposit, final Coin amount, final long expiry, final Coin rate) {

                    SendCoinsFragment.this.activity.runOnUiThread(new Runnable() {

                        @Override
                        public void run() {

                            unusedSendAmountAddress = deposit;

                            if (maybeUpdateShapeShift())
                                return;

                            if (amount.isZero()) {
                                shapeShiftStatus = ShapeShiftStatus.TOO_SMALL;
                                futureUpdate(SHAPESHIFT_LIMIT_DELAY);
                                return;
                            }

                            amountCalculatorLink.setBtcAmount(amount);
                            shapeShiftRateView.setAmount(rate, false);
                            depositAddress = deposit;
                            lastSendAmountUpdate = System.currentTimeMillis();

                            handler.post(dryrunRunnable);

                            long delay = expiry - System.currentTimeMillis() - SHAPESHIFT_SEND_AMOUNT_GAP;
                            shapeShiftStatus = ShapeShiftStatus.NONE;
                            futureUpdate(Math.max(delay, SHAPESHIFT_MIN_SEND_AMOUNT_DELAY));

                        }

                    });

                }

                @Override
                public void cancelPendingResponse() {

                    SendCoinsFragment.this.activity.runOnUiThread(new Runnable() {

                        @Override
                        public void run() {

                            unusedSendAmountAddress = null;

                            if (maybeUpdateShapeShift())
                                return;

                            Address refund = wallet.currentAddress(KeyPurpose.REFUND);
                            shapeShiftComm.sendAmount(usingShapeShiftCoin, getAddress(), amount, refund);

                        }

                    });

                }

            });

            shapeShiftStatus = ShapeShiftStatus.UPDATING;
            updateView();

            // Make sure to cancel the old transaction first if needed
            if (unusedSendAmountAddress != null)
                shapeShiftComm.cancelPending(unusedSendAmountAddress);
            else {
                Address refund = wallet.currentAddress(KeyPurpose.REFUND);
                shapeShiftComm.sendAmount(usingShapeShiftCoin, getAddress(), amount, refund);
            }

        }else{

            final Coin amount = amountCalculatorLink.getAmount();

            if (amount == null) {
                shapeShiftForeignAmountView.setAmount(null, false);
                shapeShiftWaitForAmount();
                return;
            }

            shapeShiftComm.setCallbacks(new ShapeShiftCallbacks() {

                @Override
                public void marketInfoResponse(final ShapeShiftMonetary rate, final ShapeShiftMonetary fee, final Coin max, final Coin min) {

                    SendCoinsFragment.this.activity.runOnUiThread(new Runnable() {

                        @Override
                        public void run() {

                            if (maybeUpdateShapeShift())
                                return;

                            try {

                                ShapeShiftMonetary expectedAmount = new ShapeShiftMonetary(amount, rate);
                                expectedAmount.subEqual(fee);

                                if (expectedAmount.getValue() < 0)
                                    expectedAmount = new ShapeShiftMonetary(0, usingShapeShiftCoin.getExponent());

                                shapeShiftForeignAmountView.setAmount(expectedAmount, false);
                                shapeShiftRateView.setAmount(rate.toCoinRate(), false);

                                if ((amount.isGreaterThan(min) || amount.equals(min))
                                        && (amount.isLessThan(max) || amount.equals(max))) {

                                    shapeShiftStatus = ShapeShiftStatus.NONE;
                                    futureUpdate(SHAPESHIFT_SHIFT_DELAY);

                                }else{

                                    shapeShiftStatus = ShapeShiftStatus.OUTSIDE_LIMITS;
                                    limitMin = min;
                                    limitMax = max;
                                    futureUpdate(SHAPESHIFT_LIMIT_DELAY);

                                }

                            } catch (ArithmeticException x) {
                                shapeShiftStatus = ShapeShiftStatus.PARSE_ERROR;
                                futureUpdate(SHAPESHIFT_ERROR_DELAY);
                            }


                        }

                    });

                }

            });

            shapeShiftStatus = ShapeShiftStatus.UPDATING;
            updateView();
            shapeShiftComm.marketInfo(usingShapeShiftCoin);

        }

    }

    private void setShapeShiftNoUpdate(ShapeShiftCoin coin, Monetary foreignAmount) {

        usingShapeShiftCoin = coin;

        shapeShiftForeignAmountView.setCurrencySymbol(coin.getCoinCode());
        shapeShiftForeignAmountView.setInputFormat(coin.getMonetaryFormat());
        shapeShiftForeignAmountView.setHintAndFormat(coin.getMonetaryFormat(), new ShapeShiftMonetary(0, coin.getExponent()));

        if (foreignAmount != null)
            shapeShiftForeignAmountView.setAmount(foreignAmount, false);

        shapeShiftForeignTitle.setText(coin.getCoinCode() + " " + getString(R.string.send_coins_fragment_shapeshift_foreign_label));

    }

    private void setShapeShift(ShapeShiftCoin coin, boolean isExactForeignAmountLocal, Monetary foreignAmount) {

        setShapeShiftNoUpdate(coin, foreignAmount);
        updateShapeShift(isExactForeignAmountLocal);

    }

    private void validateReceivingAddress(boolean updateShapeshift)
	{
		try
		{
			final String addressStr = receivingAddressView.getText().toString().trim();

            if (!addressStr.isEmpty()){

                List<CoinDetails> networks = Address.getCoinsFromAddress(addressStr);

                if (networks == null)
                    return;

                destCoinSpinnerAdapter.addAll(networks);

                if (updateShapeshift) {
                    if (networks.get(0).isShapeShift())
                        setShapeShift((ShapeShiftCoin) networks.get(0), isExactForeignAmount, null);
                    else
                        usingShapeShiftCoin = null;
                }

				final String label = AddressBookProvider.resolveLabel(activity, addressStr);
				validatedAddress = new AddressAndLabel(networks, addressStr, label);
				receivingAddressView.setText(null);

			}
		}
		catch (final AddressFormatException x)
		{
			// swallow
		}
	}

	private void handleCancel()
	{
		if (state == null || state.compareTo(State.INPUT) <= 0)
			activity.setResult(Activity.RESULT_CANCELED);

		activity.finish();
	}

	private boolean isPayeePlausible()
	{
		if (paymentIntent.hasOutputs())
			return true;

		if (validatedAddress != null)
			return true;

		return false;
	}

	private boolean isAmountPlausible()
	{
		if (dryrunTransaction != null)
			return dryrunException == null;
		else if (paymentIntent.mayEditAmount())
			return amountCalculatorLink.hasAmount();
		else
			return paymentIntent.hasAmount();
	}

	private boolean isPasswordPlausible()
	{
		if (!wallet.isEncrypted())
			return true;

		return !privateKeyPasswordView.getText().toString().trim().isEmpty();
	}

    private boolean isShapeShiftPlausible() {
        return usingShapeShiftCoin == null
                || (
                (!isExactForeignAmount || depositAddress != null)
                        && (shapeShiftStatus == ShapeShiftStatus.NONE || shapeShiftStatus == ShapeShiftStatus.FUTURE_UPDATE)
        );

    }

	private boolean everythingPlausible()
	{
		return state == State.INPUT && isPayeePlausible() && isAmountPlausible() && isPasswordPlausible() && isShapeShiftPlausible();
	}

	private void requestFocusFirst()
	{
		if (!isPayeePlausible())
			receivingAddressView.requestFocus();
		else if (!isAmountPlausible() && (usingShapeShiftCoin == null || !isExactForeignAmount))
			amountCalculatorLink.requestFocus();
		else if (!isPasswordPlausible())
			privateKeyPasswordView.requestFocus();
		else if (everythingPlausible())
			viewGo.requestFocus();
		else if (usingShapeShiftCoin == null)
			log.warn("unclear focus");
	}

	private void handleGo()
	{
		privateKeyBadPasswordView.setVisibility(View.INVISIBLE);

        if (usingShapeShiftCoin != null && !isExactForeignAmount && depositAddress == null) {
            // We need to finally get the deposit address to shift to.

            setState(State.FINALISE_SHAPESHIFT);

            final ShapeShiftComm shapeShiftComm = new ShapeShiftComm();

            shapeShiftComm.setCallbacks(new ShapeShiftComm.Callbacks() {

                @Override
                public void shiftResponse(final Address deposit) {

                    SendCoinsFragment.this.activity.runOnUiThread(new Runnable() {

                        @Override
                        public void run() {

                            depositAddress = deposit;
                            handleGo();

                        }

                    });

                }

                @Override
                public void networkError(final int networkCode, final String text) {

                    SendCoinsFragment.this.activity.runOnUiThread(new Runnable() {

                        @Override
                        public void run() {

                            handleShapeShiftError(networkCode, text);
                            setState(State.INPUT);
                            futureUpdate(SHAPESHIFT_ERROR_DELAY);

                        }

                    });

                }

            });

            Address refund = wallet.currentAddress(KeyPurpose.REFUND);
            shapeShiftComm.shift(usingShapeShiftCoin, getAddress(), refund);

            return;

        }

        if (wallet.isEncrypted()) {

			new DeriveKeyTask(backgroundHandler)
			{
				@Override
				protected void onSuccess(final KeyParameter encryptionKey, final boolean wasChanged)
				{
					if (wasChanged)
						application.backupWallet();
					signAndSendPayment(encryptionKey);
				}
			}.deriveKey(wallet, privateKeyPasswordView.getText().toString().trim());

			setState(State.DECRYPTING);
		}
		else
		{
			signAndSendPayment(null);
		}
	}

	private void signAndSendPayment(final KeyParameter encryptionKey)
	{
		setState(State.SIGNING);

        // Ensure the address we want is used
        Address addressReplace = null;

        if (usingShapeShiftCoin != null)
            addressReplace = depositAddress;
        else if (validatedAddress != null)
            addressReplace = validatedAddress.address;

		// final payment intent
		final PaymentIntent finalPaymentIntent = paymentIntent.mergeWithEditedValues(amountCalculatorLink.getAmount(), addressReplace);
		final Coin finalAmount = finalPaymentIntent.getAmount();

		// prepare send request
		final SendRequest sendRequest = finalPaymentIntent.toSendRequest();
		sendRequest.emptyWallet = paymentIntent.mayEditAmount() && finalAmount.equals(wallet.getBalance(BalanceType.AVAILABLE));
		sendRequest.feePerKb = feeCategory.feePerKb;
		sendRequest.memo = validatedAddress == null ? paymentIntent.memo : validatedAddress.label;
		sendRequest.exchangeRate = amountCalculatorLink.getExchangeRate();
		sendRequest.aesKey = encryptionKey;

		new SendCoinsOfflineTask(wallet, backgroundHandler)
		{
			@Override
			protected void onSuccess(final Transaction transaction)
			{
				sentTransaction = transaction;

				setState(State.SENDING);

				sentTransaction.getConfidence().addEventListener(sentTransactionConfidenceListener);

				final Address refundAddress = paymentIntent.standard == Standard.BIP70 ? wallet.freshAddress(KeyPurpose.REFUND) : null;
				final Payment payment = PaymentProtocol.createPaymentMessage(Arrays.asList(new Transaction[] { sentTransaction }), finalAmount,
						refundAddress, null, paymentIntent.payeeData);

				if (directPaymentEnableView.isChecked())
					directPay(payment);

				application.broadcastTransaction(sentTransaction);

				final ComponentName callingActivity = activity.getCallingActivity();
				if (callingActivity != null)
				{
					log.info("returning result to calling activity: {}", callingActivity.flattenToString());

					final Intent result = new Intent();
					BitcoinIntegration.transactionHashToResult(result, sentTransaction.getHashAsString());
					if (paymentIntent.standard == Standard.BIP70)
						BitcoinIntegration.paymentToResult(result, payment.toByteArray());
					activity.setResult(Activity.RESULT_OK, result);
				}
			}

			private void directPay(final Payment payment)
			{
				final DirectPaymentTask.ResultCallback callback = new DirectPaymentTask.ResultCallback()
				{
					@Override
					public void onResult(final boolean ack)
					{
						directPaymentAck = ack;

						if (state == State.SENDING)
							setState(State.SENT);

                        // If we sent to a sendAmount deposit address, we don't need to cancel
                        if (usingShapeShiftCoin != null && isExactForeignAmount)
                            unusedSendAmountAddress = null;

						updateView();
					}

					@Override
					public void onFail(final int messageResId, final Object... messageArgs)
					{
						final DialogBuilder dialog = DialogBuilder.warn(activity, R.string.send_coins_fragment_direct_payment_failed_title);
						dialog.setMessage(paymentIntent.paymentUrl + "\n" + getString(messageResId, messageArgs) + "\n\n"
								+ getString(R.string.send_coins_fragment_direct_payment_failed_msg));
						dialog.setPositiveButton(R.string.button_retry, new DialogInterface.OnClickListener()
						{
							@Override
							public void onClick(final DialogInterface dialog, final int which)
							{
								directPay(payment);
							}
						});
						dialog.setNegativeButton(R.string.button_dismiss, null);
						dialog.show();
					}
				};

				if (paymentIntent.isHttpPaymentUrl())
				{
					new DirectPaymentTask.HttpPaymentTask(backgroundHandler, callback, paymentIntent.paymentUrl, application.httpUserAgent())
							.send(payment);
				}
				else if (paymentIntent.isBluetoothPaymentUrl() && bluetoothAdapter != null && bluetoothAdapter.isEnabled())
				{
					new DirectPaymentTask.BluetoothPaymentTask(backgroundHandler, callback, bluetoothAdapter,
							Bluetooth.getBluetoothMac(paymentIntent.paymentUrl)).send(payment);
				}
			}

			@Override
			protected void onInsufficientMoney(final Coin missing)
			{
                returnToInputAndUpdate();

				final Coin estimated = wallet.getBalance(BalanceType.ESTIMATED);
				final Coin available = wallet.getBalance(BalanceType.AVAILABLE);
				final Coin pending = estimated.subtract(available);

				final MonetaryFormat btcFormat = config.getFormat();

				final DialogBuilder dialog = DialogBuilder.warn(activity, R.string.send_coins_fragment_insufficient_money_title);
				final StringBuilder msg = new StringBuilder();
				msg.append(getString(R.string.send_coins_fragment_insufficient_money_msg1, btcFormat.format(missing)));

				if (pending.signum() > 0)
					msg.append("\n\n").append(getString(R.string.send_coins_fragment_pending, btcFormat.format(pending)));
				if (paymentIntent.mayEditAmount())
					msg.append("\n\n").append(getString(R.string.send_coins_fragment_insufficient_money_msg2));
				dialog.setMessage(msg);
				if (paymentIntent.mayEditAmount())
				{
					dialog.setPositiveButton(R.string.send_coins_options_empty, new DialogInterface.OnClickListener()
					{
						@Override
						public void onClick(final DialogInterface dialog, final int which)
						{
							handleEmpty();
						}
					});
					dialog.setNegativeButton(R.string.button_cancel, null);
				}
				else
				{
					dialog.setNeutralButton(R.string.button_dismiss, null);
				}
				dialog.show();
			}

			@Override
			protected void onInvalidKey()
			{
                returnToInputAndUpdate();

				privateKeyBadPasswordView.setVisibility(View.VISIBLE);
				privateKeyPasswordView.requestFocus();
			}

			@Override
			protected void onEmptyWalletFailed()
			{
                returnToInputAndUpdate();

				final DialogBuilder dialog = DialogBuilder.warn(activity, R.string.send_coins_fragment_empty_wallet_failed_title);
				dialog.setMessage(R.string.send_coins_fragment_hint_empty_wallet_failed);
				dialog.setNeutralButton(R.string.button_dismiss, null);
				dialog.show();
			}

			@Override
			protected void onFailure(Exception exception)
			{
				setState(State.FAILED);

				final DialogBuilder dialog = DialogBuilder.warn(activity, R.string.send_coins_error_msg);
				dialog.setMessage(exception.toString());
				dialog.setNeutralButton(R.string.button_dismiss, null);
				dialog.show();
			}
		}.sendCoinsOffline(sendRequest); // send asynchronously
	}

	private void handleScan()
	{
		startActivityForResult(new Intent(activity, ScanActivity.class), REQUEST_CODE_SCAN);
	}

	private void handleFeeCategory(final FeeCategory feeCategory)
	{
		this.feeCategory = feeCategory;

		updateView();
		handler.post(dryrunRunnable);
	}

	private void handleEmpty()
	{
		final Coin available = wallet.getBalance(BalanceType.AVAILABLE);
		amountCalculatorLink.setBtcAmount(available);

        updateShapeShift(false);

		updateView();
		handler.post(dryrunRunnable);
	}

	private Runnable dryrunRunnable = new Runnable()
	{
		@Override
		public void run()
		{
			if (state == State.INPUT)
				executeDryrun();

			updateView();
		}

		private void executeDryrun()
		{
			dryrunTransaction = null;
			dryrunException = null;

			final Coin amount = amountCalculatorLink.getAmount();
			if (amount != null)
			{
				try
				{
					final Address dummy = wallet.currentReceiveAddress(); // won't be used, tx is never committed
					final SendRequest sendRequest = paymentIntent.mergeWithEditedValues(amount, dummy).toSendRequest();
					sendRequest.signInputs = false;
					sendRequest.emptyWallet = paymentIntent.mayEditAmount() && amount.equals(wallet.getBalance(BalanceType.AVAILABLE));
					sendRequest.feePerKb = feeCategory.feePerKb;
					wallet.completeTx(sendRequest);
					dryrunTransaction = sendRequest.tx;
				}
				catch (final Exception x)
				{
					dryrunException = x;
				}
			}
		}
	};

    private void returnToInputAndUpdate() {

        setState(State.INPUT);
        updateShapeShift(isExactForeignAmount);

    }

	private void setState(final State state)
	{
		this.state = state;

        if (state != State.INPUT && activeShapeShiftComm != null)
            activeShapeShiftComm.stop();

		activity.invalidateOptionsMenu();
		updateView();
	}

	private void updateView()
	{
		if (!isResumed())
			return;

		if (paymentIntent != null)
		{
			final MonetaryFormat btcFormat = config.getFormat();

			getView().setVisibility(View.VISIBLE);

			if (paymentIntent.hasPayee())
			{
				payeeNameView.setVisibility(View.VISIBLE);
				payeeNameView.setText(paymentIntent.payeeName);

				payeeVerifiedByView.setVisibility(View.VISIBLE);
				final String verifiedBy = paymentIntent.payeeVerifiedBy != null ? paymentIntent.payeeVerifiedBy
						: getString(R.string.send_coins_fragment_payee_verified_by_unknown);
				payeeVerifiedByView.setText(Constants.CHAR_CHECKMARK
						+ String.format(getString(R.string.send_coins_fragment_payee_verified_by), verifiedBy));
			}
			else
			{
				payeeNameView.setVisibility(View.GONE);
				payeeVerifiedByView.setVisibility(View.GONE);
			}

			if (paymentIntent.hasOutputs())
			{
				payeeGroup.setVisibility(View.VISIBLE);
				receivingAddressView.setVisibility(View.GONE);
				receivingStaticView.setVisibility(!paymentIntent.hasPayee() || paymentIntent.payeeVerifiedBy == null ? View.VISIBLE : View.GONE);

				receivingStaticLabelView.setText(paymentIntent.memo);

				if (paymentIntent.hasAddress())
					receivingStaticAddressView.setText(WalletUtils.formatAddress(paymentIntent.getAddress(), Constants.ADDRESS_FORMAT_GROUP_SIZE,
							Constants.ADDRESS_FORMAT_LINE_SIZE));
				else
					receivingStaticAddressView.setText(R.string.send_coins_fragment_receiving_address_complex);
			}
			else if (validatedAddress != null)
			{
				payeeGroup.setVisibility(View.VISIBLE);
				receivingAddressView.setVisibility(View.GONE);
				receivingStaticView.setVisibility(View.VISIBLE);

				receivingStaticAddressView.setText(WalletUtils.formatAddress(validatedAddress.address, Constants.ADDRESS_FORMAT_GROUP_SIZE,
						Constants.ADDRESS_FORMAT_LINE_SIZE));
				final String addressBookLabel = AddressBookProvider.resolveLabel(activity, validatedAddress.address.toBase58());
				final String staticLabel;
				if (addressBookLabel != null)
					staticLabel = addressBookLabel;
				else if (validatedAddress.label != null)
					staticLabel = validatedAddress.label;
				else
					staticLabel = getString(R.string.address_unlabeled);
				receivingStaticLabelView.setText(staticLabel);
				receivingStaticLabelView.setTextColor(getResources().getColor(
						validatedAddress.label != null ? R.color.fg_significant : R.color.fg_insignificant));
			}
			else if (paymentIntent.standard == null)
			{
				payeeGroup.setVisibility(View.VISIBLE);
				receivingStaticView.setVisibility(View.GONE);
				receivingAddressView.setVisibility(View.VISIBLE);
			}
			else
			{
				payeeGroup.setVisibility(View.GONE);
			}

            int shapeShiftVisibility = (usingShapeShiftCoin != null) ? View.VISIBLE : View.GONE;
            shapeShiftTitles.setVisibility(shapeShiftVisibility);
            shapeShiftAmounts.setVisibility(shapeShiftVisibility);

			receivingAddressView.setEnabled(state == State.INPUT);

			amountGroup.setVisibility(paymentIntent.hasAmount() || (state != null && state.compareTo(State.INPUT) >= 0) ? View.VISIBLE : View.GONE);
			amountCalculatorLink.setEnabled(state == State.INPUT && paymentIntent.mayEditAmount());

            shapeShiftForeignAmountView.setEnabled(state == State.INPUT);
            destCoinSpinner.setEnabled(state == State.INPUT);

			final boolean directPaymentVisible;
			if (paymentIntent.hasPaymentUrl() && usingShapeShiftCoin == null)
			{
				if (paymentIntent.isBluetoothPaymentUrl())
					directPaymentVisible = bluetoothAdapter != null;
				else
					directPaymentVisible = !Constants.BUG_OPENSSL_HEARTBLEED;
			}
			else
			{
				directPaymentVisible = false;
			}
			directPaymentEnableView.setVisibility(directPaymentVisible ? View.VISIBLE : View.GONE);
			directPaymentEnableView.setEnabled(state == State.INPUT);

            // Set errors

			hintView.setVisibility(View.GONE);
            shapeShiftHintView.setVisibility(View.GONE);
            shapeShiftEstView.setVisibility(View.GONE);

			if (state == State.INPUT)
			{
				if (paymentIntent.mayEditAddress() && validatedAddress == null && !receivingAddressView.getText().toString().trim().isEmpty())
				{
					hintView.setTextColor(getResources().getColor(R.color.fg_error));
					hintView.setVisibility(View.VISIBLE);
					hintView.setText(R.string.send_coins_fragment_receiving_address_error);
				}
				else if (dryrunException != null)
				{
					hintView.setTextColor(getResources().getColor(R.color.fg_error));
					hintView.setVisibility(View.VISIBLE);
					if (dryrunException instanceof DustySendRequested)
						hintView.setText(getString(R.string.send_coins_fragment_hint_dusty_send));
					else if (dryrunException instanceof InsufficientMoneyException)
						hintView.setText(getString(R.string.send_coins_fragment_hint_insufficient_money,
								btcFormat.format(((InsufficientMoneyException) dryrunException).missing)));
					else if (dryrunException instanceof CouldNotAdjustDownwards)
						hintView.setText(getString(R.string.send_coins_fragment_hint_empty_wallet_failed));
					else
						hintView.setText(dryrunException.toString());
				}
				else if (dryrunTransaction != null && dryrunTransaction.getFee() != null)
				{
					hintView.setTextColor(getResources().getColor(R.color.fg_insignificant));
					hintView.setVisibility(View.VISIBLE);
					hintView.setText(getString(R.string.send_coins_fragment_hint_fee, btcFormat.format(dryrunTransaction.getFee())));
				}
				else if (paymentIntent.mayEditAddress() && validatedAddress != null && wallet.isPubKeyHashMine(validatedAddress.address.getHash160()))
				{
					hintView.setTextColor(getResources().getColor(R.color.fg_insignificant));
					hintView.setVisibility(View.VISIBLE);
					hintView.setText(R.string.send_coins_fragment_receiving_address_own);
				}

                if (usingShapeShiftCoin != null) {

                    if (shapeShiftStatus != ShapeShiftStatus.NONE) {

                        shapeShiftHintView.setTextColor(getResources().getColor(R.color.fg_error));

                        if (shapeShiftStatus == ShapeShiftStatus.OTHER_ERROR)
                            shapeShiftHintView.setText(shapeShiftStatusText);
                        else if (shapeShiftStatus == ShapeShiftStatus.CONNECTION_ERROR)
                            shapeShiftHintView.setText(R.string.send_coins_fragment_hint_shapeshift_connection_error);
                        else if (shapeShiftStatus == ShapeShiftStatus.OUTSIDE_LIMITS)
                            shapeShiftHintView.setText(
                                    getString(
                                            R.string.send_coins_fragment_hint_shapeshift_outside_limits,
                                            btcFormat.format(limitMin),
                                            btcFormat.format(limitMax)
                                    ));
                        else if (shapeShiftStatus == ShapeShiftStatus.TOO_SMALL)
                            shapeShiftHintView.setText(R.string.send_coins_fragment_hint_shapeshift_too_small);
                        else if (shapeShiftStatus == ShapeShiftStatus.PARSE_ERROR)
                            shapeShiftHintView.setText(R.string.send_coins_fragment_hint_shapeshift_parse_error);
                        else {

                            if (!isExactForeignAmount)
                                shapeShiftEstView.setVisibility(View.VISIBLE);

                            shapeShiftHintView.setTextColor(getResources().getColor(R.color.fg_significant));

                            if (shapeShiftStatus == ShapeShiftStatus.UPDATING)
                                shapeShiftHintView.setText(R.string.send_coins_fragment_hint_shapeshift_updating);
                            else if (shapeShiftStatus == ShapeShiftStatus.FUTURE_UPDATE) {

                                String timeToWait;

                                if (secondsToUpdate >= 60) {

                                    long minutes = secondsToUpdate / 60 + secondsToUpdate % 60 / 30;
                                    timeToWait = String.format("%d minute%s", minutes, minutes == 1 ? "" : "s");

                                }else
                                    timeToWait = String.format("%d second%s", secondsToUpdate, secondsToUpdate == 1 ? "" : "s");

                                shapeShiftHintView.setText(getString(
                                        R.string.send_coins_fragment_hint_shapeshift_future_update, timeToWait
                                ));

                            }

                        }

                        shapeShiftHintView.setVisibility(View.VISIBLE);

                    }
                }
			}

			if (sentTransaction != null)
			{
				sentTransactionView.setVisibility(View.VISIBLE);
				sentTransactionAdapter.setFormat(btcFormat);
				sentTransactionAdapter.replace(sentTransaction);
				sentTransactionAdapter.bindViewHolder(sentTransactionViewHolder, 0);
			}
			else
			{
				sentTransactionView.setVisibility(View.GONE);
			}

			if (directPaymentAck != null)
			{
				directPaymentMessageView.setVisibility(View.VISIBLE);
				directPaymentMessageView.setText(directPaymentAck ? R.string.send_coins_fragment_direct_payment_ack
						: R.string.send_coins_fragment_direct_payment_nack);
			}
			else
			{
				directPaymentMessageView.setVisibility(View.GONE);
			}

			viewCancel.setEnabled(state != State.REQUEST_PAYMENT_REQUEST && state != State.DECRYPTING && state != State.SIGNING && state != State.FINALISE_SHAPESHIFT);
			viewGo.setEnabled(everythingPlausible() && dryrunTransaction != null);

			if (state == null || state == State.REQUEST_PAYMENT_REQUEST)
			{
				viewCancel.setText(R.string.button_cancel);
				viewGo.setText(null);
			}
			else if (state == State.INPUT)
			{
				viewCancel.setText(R.string.button_cancel);
				viewGo.setText(R.string.send_coins_fragment_button_send);
			}
			else if (state == State.DECRYPTING)
			{
				viewCancel.setText(R.string.button_cancel);
				viewGo.setText(R.string.send_coins_fragment_state_decrypting);
			}
            else if (state == State.FINALISE_SHAPESHIFT) {
                viewCancel.setText(R.string.button_cancel);
                viewGo.setText(R.string.send_coins_fragment_state_finalise_shapeshift);
            }
			else if (state == State.SIGNING)
			{
				viewCancel.setText(R.string.button_cancel);
				viewGo.setText(R.string.send_coins_preparation_msg);
			}
			else if (state == State.SENDING)
			{
				viewCancel.setText(R.string.send_coins_fragment_button_back);
				viewGo.setText(R.string.send_coins_sending_msg);
			}
			else if (state == State.SENT)
			{
				viewCancel.setText(R.string.send_coins_fragment_button_back);
				viewGo.setText(R.string.send_coins_sent_msg);
			}
			else if (state == State.FAILED)
			{
				viewCancel.setText(R.string.send_coins_fragment_button_back);
				viewGo.setText(R.string.send_coins_failed_msg);
			}

			final boolean privateKeyPasswordViewVisible = (state == State.INPUT || state == State.FINALISE_SHAPESHIFT || state == State.DECRYPTING) && wallet.isEncrypted();
			privateKeyPasswordViewGroup.setVisibility(privateKeyPasswordViewVisible ? View.VISIBLE : View.GONE);
			privateKeyPasswordView.setEnabled(state == State.INPUT);

			// focus linking
			final int activeAmountViewId = amountCalculatorLink.activeTextView().getId();
			receivingAddressView.setNextFocusDownId(activeAmountViewId);
			receivingAddressView.setNextFocusForwardId(activeAmountViewId);
			amountCalculatorLink.setNextFocusId(privateKeyPasswordViewVisible ? R.id.send_coins_private_key_password : R.id.send_coins_go);
			privateKeyPasswordView.setNextFocusUpId(activeAmountViewId);
			privateKeyPasswordView.setNextFocusDownId(R.id.send_coins_go);
			privateKeyPasswordView.setNextFocusForwardId(R.id.send_coins_go);
			viewGo.setNextFocusUpId(privateKeyPasswordViewVisible ? R.id.send_coins_private_key_password : activeAmountViewId);
		}
		else
		{
			getView().setVisibility(View.GONE);
		}
	}

	private void initStateFromIntentExtras(final Bundle extras)
	{
		final PaymentIntent paymentIntent = extras.getParcelable(SendCoinsActivity.INTENT_EXTRA_PAYMENT_INTENT);
		final FeeCategory feeCategory = (FeeCategory) extras.getSerializable(SendCoinsActivity.INTENT_EXTRA_FEE_CATEGORY);

		if (feeCategory != null)
		{
			log.info("got fee category {}", feeCategory);
			this.feeCategory = feeCategory;
		}

		updateStateFrom(paymentIntent);
	}

	private void initStateFromBitcoinUri(final Uri bitcoinUri)
	{
		final String input = bitcoinUri.toString();

		new StringInputParser(input)
		{
			@Override
			protected void handlePaymentIntent(final PaymentIntent paymentIntent)
			{
				updateStateFrom(paymentIntent);
			}

			@Override
			protected void handlePrivateKey(final VersionedChecksummedBytes key)
			{
				throw new UnsupportedOperationException();
			}

			@Override
			protected void handleDirectTransaction(final Transaction transaction) throws VerificationException
			{
				throw new UnsupportedOperationException();
			}

			@Override
			protected void error(final int messageResId, final Object... messageArgs)
			{
				dialog(activity, activityDismissListener, 0, messageResId, messageArgs);
			}
		}.parse();
	}

	private void initStateFromPaymentRequest(final String mimeType, final byte[] input)
	{
		new BinaryInputParser(mimeType, input)
		{
			@Override
			protected void handlePaymentIntent(final PaymentIntent paymentIntent)
			{
				updateStateFrom(paymentIntent);
			}

			@Override
			protected void error(final int messageResId, final Object... messageArgs)
			{
				dialog(activity, activityDismissListener, 0, messageResId, messageArgs);
			}
		}.parse();
	}

	private void initStateFromIntentUri(final String mimeType, final Uri bitcoinUri)
	{
		try
		{
			final InputStream is = contentResolver.openInputStream(bitcoinUri);

			new StreamInputParser(mimeType, is)
			{
				@Override
				protected void handlePaymentIntent(final PaymentIntent paymentIntent)
				{
					updateStateFrom(paymentIntent);
				}

				@Override
				protected void error(final int messageResId, final Object... messageArgs)
				{
					dialog(activity, activityDismissListener, 0, messageResId, messageArgs);
				}
			}.parse();
		}
		catch (final FileNotFoundException x)
		{
			throw new RuntimeException(x);
		}
	}

	public void updateStateFrom(final PaymentIntent paymentIntent)
	{
		log.info("got {}", paymentIntent);

		this.paymentIntent = paymentIntent;

		validatedAddress = null;
		directPaymentAck = null;

		// delay these actions until fragment is resumed
		handler.post(new Runnable()
		{
			@Override
			public void run()
			{
				if (paymentIntent.hasPaymentRequestUrl() && paymentIntent.isBluetoothPaymentRequestUrl())
				{
					if (bluetoothAdapter.isEnabled())
						requestPaymentRequest();
					else
						// ask for permission to enable bluetooth
						startActivityForResult(new Intent(BluetoothAdapter.ACTION_REQUEST_ENABLE), REQUEST_CODE_ENABLE_BLUETOOTH_FOR_PAYMENT_REQUEST);
				}
				else if (paymentIntent.hasPaymentRequestUrl() && paymentIntent.isHttpPaymentRequestUrl() && !Constants.BUG_OPENSSL_HEARTBLEED)
				{
					requestPaymentRequest();
				}
				else
				{
					setState(State.INPUT);

					receivingAddressView.setText(null);
                    if (paymentIntent.networks != null) {
                        destCoinSpinnerAdapter.clear();
                        destCoinSpinnerAdapter.addAll(paymentIntent.networks);
                    }

                    if (paymentIntent.networks != null && paymentIntent.networks.get(0).isShapeShift()) {

                        Monetary amount = paymentIntent.getShapeShiftAmount();
                        setShapeShift((ShapeShiftCoin) paymentIntent.networks.get(0), amount != null, amount);
                        amountCalculatorLink.setBtcAmount(Coin.ZERO);

                    }else {
                        usingShapeShiftCoin = null;
                        amountCalculatorLink.setBtcAmount(paymentIntent.getAmount());

                        if (paymentIntent.isBluetoothPaymentUrl())
                            directPaymentEnableView.setChecked(bluetoothAdapter != null && bluetoothAdapter.isEnabled());
                        else if (paymentIntent.isHttpPaymentUrl())
                            directPaymentEnableView.setChecked(!Constants.BUG_OPENSSL_HEARTBLEED);
                    }

					requestFocusFirst();
					updateView();
					handler.post(dryrunRunnable);
				}
			}
		});
	}

	private void requestPaymentRequest()
	{
		final String host;
		if (!Bluetooth.isBluetoothUrl(paymentIntent.paymentRequestUrl))
			host = Uri.parse(paymentIntent.paymentRequestUrl).getHost();
		else
			host = Bluetooth.decompressMac(Bluetooth.getBluetoothMac(paymentIntent.paymentRequestUrl));

		ProgressDialogFragment.showProgress(fragmentManager, getString(R.string.send_coins_fragment_request_payment_request_progress, host));
		setState(State.REQUEST_PAYMENT_REQUEST);

		final RequestPaymentRequestTask.ResultCallback callback = new RequestPaymentRequestTask.ResultCallback()
		{
			@Override
			public void onPaymentIntent(final PaymentIntent paymentIntent)
			{
				ProgressDialogFragment.dismissProgress(fragmentManager);

				if (SendCoinsFragment.this.paymentIntent.isExtendedBy(paymentIntent))
				{
					// success
					setState(State.INPUT);
					updateStateFrom(paymentIntent);
					updateView();
					handler.post(dryrunRunnable);
				}
				else
				{
					final StringBuilder reasons = new StringBuilder();
					if (!SendCoinsFragment.this.paymentIntent.equalsAddress(paymentIntent))
						reasons.append("address");
					if (!SendCoinsFragment.this.paymentIntent.equalsAmount(paymentIntent))
						reasons.append(reasons.length() == 0 ? "" : ", ").append("amount");
					if (reasons.length() == 0)
						reasons.append("unknown");

					final DialogBuilder dialog = DialogBuilder.warn(activity, R.string.send_coins_fragment_request_payment_request_failed_title);
					dialog.setMessage(getString(R.string.send_coins_fragment_request_payment_request_wrong_signature) + "\n\n" + reasons);
					dialog.singleDismissButton(new DialogInterface.OnClickListener()
					{
						@Override
						public void onClick(final DialogInterface dialog, final int which)
						{
							handleCancel();
						}
					});
					dialog.show();

					log.info("BIP72 trust check failed: {}", reasons);
				}
			}

			@Override
			public void onFail(final int messageResId, final Object... messageArgs)
			{
				ProgressDialogFragment.dismissProgress(fragmentManager);

				final DialogBuilder dialog = DialogBuilder.warn(activity, R.string.send_coins_fragment_request_payment_request_failed_title);
				dialog.setMessage(getString(messageResId, messageArgs));
				dialog.setPositiveButton(R.string.button_retry, new DialogInterface.OnClickListener()
				{
					@Override
					public void onClick(final DialogInterface dialog, final int which)
					{
						requestPaymentRequest();
					}
				});
				dialog.setNegativeButton(R.string.button_dismiss, new DialogInterface.OnClickListener()
				{
					@Override
					public void onClick(final DialogInterface dialog, final int which)
					{
						if (!paymentIntent.hasOutputs())
							handleCancel();
						else
							setState(State.INPUT);
					}
				});
				dialog.show();
			}
		};

		if (!Bluetooth.isBluetoothUrl(paymentIntent.paymentRequestUrl))
			new RequestPaymentRequestTask.HttpRequestTask(backgroundHandler, callback, application.httpUserAgent())
					.requestPaymentRequest(paymentIntent.paymentRequestUrl);
		else
			new RequestPaymentRequestTask.BluetoothRequestTask(backgroundHandler, callback, bluetoothAdapter)
					.requestPaymentRequest(paymentIntent.paymentRequestUrl);
	}
}
