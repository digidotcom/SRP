﻿/*  This file is part of NETSRP.
 *
 *  NETSRP is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU Lesser General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  NETSRP is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public License
 *  along with Foobar.  If not, see <http://www.gnu.org/licenses/>.
 */

using System.Text;


namespace SRP
{
    public static class Constants
    {
        public static SrpBigInteger N = new SrpBigInteger("EEAF0AB9ADB38DD69C33F80AFA8FC5E86072618775FF3C0B9EA2314C" + 
            "9C256576D674DF7496EA81D3383B4813D692C6E0E0D5D8E250B98BE4" +
            "8E495C1D6089DAD15DC7D7B46154D6B6CE8EF4AD69B15D4982559B29" +
            "7BCF1885C529F566660E57EC68EDBC3C05726CC02FD4CBF4976EAA9A" +
            "FD5138FE8376435B9FC61D2FC0EB06E3", 16);


        public static SrpBigInteger g = new SrpBigInteger(2);

        public static byte[] Seperator = new ASCIIEncoding().GetBytes(":");

        public static string API_USERNAME = "apiservice";

        public static int LENGTH_SALT = 4;
        public static int LENGTH_VERIFIER = 128;
    }

}
