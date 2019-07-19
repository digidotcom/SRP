/*
 * Copyright 2019, Digi International Inc.
 * 
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

using System;
using System.Security.Cryptography;
using System.Text;

namespace SRP
{
	public class Utils
	{
		/// <summary>
		/// Generates and returns a random salt number.
		/// </summary>
		/// <returns>Random salt number.</returns>
		public static byte[] GenerateSalt()
		{
			byte[] salt = new byte[Constants.LENGTH_SALT];
			RandomNumberGenerator generator = RandomNumberGenerator.Create();
			generator.GetBytes(salt);
			return salt;
		}

		/// <summary>
		/// Generates and returns a verifier from the provided salt and password.
		/// </summary>
		/// <remarks>
		/// Note that the username (I) in the XBee Bluetooth Low Energy API is fixed to
		/// <c>apiservice</c>.
		/// </remarks>
		/// <param name="salt">The salt to use.</param>
		/// <param name="password">The user password.</param>
		/// <returns>A new SRP verifier.</returns>
		public static byte[] GenerateVerifier(byte[] salt, string password)
		{
			byte[] x = Common.GenerateX(salt, Encoding.Default.GetBytes(Constants.API_USERNAME), Encoding.Default.GetBytes(password));
			byte[] verifier = new byte[Constants.LENGTH_VERIFIER];
			byte[] v = Constants.g.modPow(new SrpBigInteger(x).abs(), Constants.N).getBytes();
			Array.Copy(v, 0, verifier, verifier.Length - v.Length, v.Length);
			return verifier;
		}
	}
}
