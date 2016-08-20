/*
 * Copyright 2013-2015 the original author or authors.
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

import javax.annotation.Nullable;

import org.bitcoinj_extra.core.Address;
import org.bitcoinj_extra.core.AddressFormatException;
import org.bitcoinj_extra.core.CoinDetails;
import org.bitcoinj_extra.core.NetworkParameters;
import org.bitcoinj_extra.core.WrongNetworkException;
import org.bitcoinj_extra.params.Networks;

import android.os.Parcel;
import android.os.Parcelable;

import com.google.common.base.Objects;

import java.util.ArrayList;
import java.util.List;

import com.matthewmitchell.bitcoin_extra_wallet.Constants;
import com.matthewmitchell.bitcoin_extra_wallet.util.WalletUtils;

/**
 * @author Andreas Schildbach
 */
public class AddressAndLabel implements Parcelable
{
	public final Address address;
	public final String label;

	public AddressAndLabel(final Address address, @Nullable final String label)
	{
		this.address = address;
		this.label = label;
	}

	public AddressAndLabel(final CoinDetails addressParams, final String address, @Nullable final String label) throws WrongNetworkException,
			AddressFormatException
	{
		this(Address.fromBase58(addressParams, address), label);
	}

	public AddressAndLabel(final List<CoinDetails> addressParams, final String address, @Nullable final String label)
			throws WrongNetworkException, AddressFormatException {
		this.address = new Address(addressParams, address);
		this.label = label;
	}

	@Override
	public boolean equals(final Object o)
	{
		if (this == o)
			return true;
		if (o == null || getClass() != o.getClass())
			return false;
		final AddressAndLabel other = (AddressAndLabel) o;
		return Objects.equal(this.address, other.address) && Objects.equal(this.label, other.label);
	}

	@Override
	public int hashCode()
	{
		return Objects.hashCode(address, label);
	}

	@Override
	public int describeContents()
	{
		return 0;
	}

	@Override
	public void writeToParcel(final Parcel dest, final int flags)
	{
        List<CoinDetails> networks = address.getCoinDetails();

        dest.writeInt(networks.size());

        for (CoinDetails network: networks)
            dest.writeString(network.getId());

        dest.writeByteArray(address.getHash160());
		dest.writeString(label);
	}

	public static final Parcelable.Creator<AddressAndLabel> CREATOR = new Parcelable.Creator<AddressAndLabel>()
	{
		@Override
		public AddressAndLabel createFromParcel(final Parcel in)
		{
			return new AddressAndLabel(in);
		}

		@Override
		public AddressAndLabel[] newArray(final int size)
		{
			return new AddressAndLabel[size];
		}
	};

	private AddressAndLabel(final Parcel in)
	{

        final int paramsSize = in.readInt();
        final List<CoinDetails> addressParameters = new ArrayList(paramsSize);

        for (int x = 0; x < paramsSize; x++)
            addressParameters.add(Networks.get(in.readString()));

        final byte[] addressHash = new byte[Address.LENGTH];
        in.readByteArray(addressHash);
        address = new Address(addressParameters, addressHash);

        label = in.readString();

	}
}
