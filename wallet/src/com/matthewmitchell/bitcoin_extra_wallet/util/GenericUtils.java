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

package com.matthewmitchell.bitcoin_extra_wallet.util;

import android.content.Context;

import java.util.Currency;

import com.matthewmitchell.bitcoin_extra_wallet.Constants;

/**
 * @author Andreas Schildbach
 */
public class GenericUtils
{
	public static boolean startsWithIgnoreCase(final String string, final String prefix)
	{
		return string.regionMatches(true, 0, prefix, 0, prefix.length());
	}

	public static String currencySymbol(final String currencyCode)
	{
		try
		{
			final Currency currency = Currency.getInstance(currencyCode);
			return currency.getSymbol();
		}
		catch (final IllegalArgumentException x)
		{
			return currencyCode;
		}
	}

	public static String makeEmailText(Context context, String text) {
		return text + "\n\n" + String.format(Constants.WEBMARKET_APP_URL, context.getPackageName()) + "\n\n" + Constants.SOURCE_URL + '\n';
	}

}
