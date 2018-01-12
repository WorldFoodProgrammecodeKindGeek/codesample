package com.kindgeek.security;

import java.util.Collection;

/**
 * Created by oleh.kuprovskyi on 05.10.17.
 */
public interface SecurityAccess {
    boolean denyAccessUnlessGranted(Collection<String> roles);
}
