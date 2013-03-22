package info.staticfree.SuperGenPass.hashes;
/*
 * Copyright (C) 2010 Steve Pomeroy
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

import info.staticfree.SuperGenPass.PasswordGenerationException;

/**
 * A password hash that takes a password and a domain. Domains are optionally checked against
 * a database of known TLDs in order to generate domain-specific passwords.
 * For example, "www.example.org" and "www2.example.org" will generate the same password.
 *
 * @author Steve Pomeroy
 *
 */
public abstract class DomainBasedHash {
	private DomainResolver resolver;

	public DomainBasedHash(DomainResolver resolver) {
		this.resolver = resolver;		
	}
	
	protected String getDomain(String hostname) throws PasswordGenerationException {
		return resolver.getDomain(hostname);
	}

    /**
     * Generates a password based on the given domain and a master password. Each time the method is
     * passed a given master password / domain, it will output the same password for that pair.
     * 
     * @param masterPass
     *            master password
     * @param domain
     *            un-filtered domain (eg. www.example.org)
     * @return generated password based on the master password and the domain
     * @throws PasswordGenerationException
     *             if the criteria for generating the password are not met. Often a length or domain
     *             issue.
     */
    public abstract String generate(String masterPass, String domain, int length) throws PasswordGenerationException;
}