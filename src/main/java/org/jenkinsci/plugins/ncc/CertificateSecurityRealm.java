/*
 * The MIT License
 *
 * Copyright (c) 2011, CloudBees, Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
package org.jenkinsci.plugins.ncc;

import hudson.Extension;
import hudson.model.Descriptor;
import hudson.model.Hudson;
import hudson.security.SecurityRealm;
import org.acegisecurity.Authentication;
import org.acegisecurity.AuthenticationManager;
import org.acegisecurity.GrantedAuthority;
import org.acegisecurity.context.SecurityContextHolder;
import org.acegisecurity.providers.UsernamePasswordAuthenticationToken;
import org.acegisecurity.userdetails.UserDetails;
import org.acegisecurity.userdetails.UserDetailsService;
import org.acegisecurity.userdetails.UsernameNotFoundException;
import org.kohsuke.stapler.DataBoundConstructor;
import org.springframework.dao.DataAccessException;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * @author Miles Chen
 */
public class CertificateSecurityRealm extends SecurityRealm {
    private final String sdnKey;
    private final String sdnStrip;

    @DataBoundConstructor
    public CertificateSecurityRealm(String sdnKey, String sdnStrip) {
        this.sdnKey = sdnKey;
        this.sdnStrip = sdnStrip;
    }

    /**
     * Field of the DN to look at.
     */
    public String getSdnKey() {
        return this.sdnKey;
    }

    public String getSdnStrip() {
        return this.sdnStrip;
    }

    @Override
    public boolean canLogOut() {
        return false;
    }

    @Override
    public Filter createFilter(FilterConfig filterConfig) {
        return new Filter() {
            public void init(FilterConfig filterConfig) throws ServletException {

            }

            public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
                Authentication a;
                HttpServletRequest r = (HttpServletRequest) request;
                String sdn = r.getHeader(getSdnKey());
                String rule = getSdnStrip();

                if (sdn == null) {
                    a = Hudson.ANONYMOUS;
                } else {

                    Pattern p = Pattern.compile(rule);
                    Matcher m = p.matcher(sdn);
                    m.find();
                    String user = m.group(1);
                    user = user.toLowerCase();

                    GrantedAuthority[] authorities = new GrantedAuthority[]{
                            SecurityRealm.AUTHENTICATED_AUTHORITY
                    };
                    a = new UsernamePasswordAuthenticationToken(user, "", authorities);
                }

                SecurityContextHolder.getContext().setAuthentication(a);
                chain.doFilter(request, response);
            }

            public void destroy() {
            }
        };
    }

    @Override
    public SecurityComponents createSecurityComponents() {
        return new SecurityComponents(new AuthenticationManager() {
            public Authentication authenticate(Authentication authentication) {
                return authentication;
            }
        }, new UserDetailsService() {
            public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException, DataAccessException {
                throw new UsernameNotFoundException(username);
            }
        });
    }

    @Extension
    public static class DescriptorImpl extends Descriptor<SecurityRealm> {
        public String getDisplayName() {
            return Messages.CertificateSecurityRealm_DisplayName();
        }
    }
}
