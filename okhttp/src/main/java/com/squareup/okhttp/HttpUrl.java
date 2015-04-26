/*
 * Copyright (C) 2015 Square, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.squareup.okhttp;

import com.squareup.okhttp.internal.Util;
import java.io.EOFException;
import java.io.IOException;
import java.net.InetAddress;
import java.net.URI;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import okio.Buffer;
import okio.ByteString;

/**
 * A <a href="https://url.spec.whatwg.org/">URL</a> with an {@code http} or {@code https} scheme.
 *
 * TODO: discussion on canonicalization
 *
 * TODO: discussion on encoding-by-parts
 *
 * TODO: discussion on this vs. java.net.URL vs. java.net.URI
 */
public final class HttpUrl {
  private static final ByteString DEFAULT_ENCODE_SET = ByteString.encodeUtf8(" \"#<>?`");

  private final String scheme;
  private final String username;
  private final String password;
  private final String host;
  private final int port;
  private final List<String> path;
  private final String query;
  private final String fragment;
  private final String url;

  private HttpUrl(String scheme, String username, String password, String host, int port,
      List<String> path, String query, String fragment, String url) {
    this.scheme = scheme;
    this.username = username;
    this.password = password;
    this.host = host;
    this.port = port;
    this.path = path;
    this.query = query;
    this.fragment = fragment;
    this.url = url;
  }

  public URL url() {
    throw new UnsupportedOperationException();
  }

  public URI uri() throws IOException {
    throw new UnsupportedOperationException();
  }

  /** Returns either "http" or "https". */
  public String scheme() {
    return scheme;
  }

  public boolean isHttps() {
    return scheme.equals("https");
  }

  public String user() {
    throw new UnsupportedOperationException();
  }

  public String encodedUser() {
    throw new UnsupportedOperationException();
  }

  public String password() {
    throw new UnsupportedOperationException();
  }

  public String encodedPassword() {
    throw new UnsupportedOperationException();
  }

  /**
   * Returns the decoded (potentially non-ASCII) hostname. The returned string may contain non-ASCII
   * characters and is <strong>not suitable</strong> for DNS lookups; for that use {@link
   * #encodedHost}. For example, this may return {@code ☃.net} which is a user-displayable IDN that
   * cannot be used for DNS lookups without encoding.
   */
  public String host() {
    throw new UnsupportedOperationException();
  }

  /**
   * Returns the host address suitable for use with {@link InetAddress#getAllByName(String)}. May
   * be a regular host name ({@code android.com}), an IPv4 address ({@code 127.0.0.1}), an IPv6
   * address ({@code ::1}; note that there are no square braces), or an encoded IDN ({@code
   * xn--n3h.net}).
   */
  public String encodedHost() {
    throw new UnsupportedOperationException();
  }

  /**
   * Returns the explicitly-specified port if one was provided, or the default port for this URL's
   * scheme. For example, this returns 8443 for {@code https://square.com:8443/} and 443 for {@code
   * https://square.com/}.
   */
  public int port() {
    return port;
  }

  /**
   * Returns 80 if {@code scheme.equals("http")}, 443 if {@code scheme.equals("https")} and -1
   * otherwise.
   */
  public static int defaultPort(String scheme) {
    if (scheme.equals("http")) {
      return 80;
    } if (scheme.equals("https")) {
      return 443;
    } else {
      return -1;
    }
  }

  /**
   * Returns the entire path of this URL, encoded for use in HTTP resource resolution. The
   * returned path is always nonempty and is prefixed with {@code /}.
   */
  public String encodedPath() {
    throw new UnsupportedOperationException();
  }

  public List<String> pathSegments() {
    throw new UnsupportedOperationException();
  }

  /**
   * Returns the query of this URL, encoded for use in HTTP resource resolution. The returned string
   * may be null (for URLs with no query), empty (for URLs with an empty query) or non-empty (all
   * other URLs).
   */
  public String encodedQuery() {
    throw new UnsupportedOperationException();
  }

  /**
   * Returns the first query parameter named {@code name} decoded using UTF-8, or null if there is
   * no such query parameter.
   */
  public String queryParameter(String name) {
    throw new UnsupportedOperationException();
  }

  public Set<String> queryParameterNames() {
    throw new UnsupportedOperationException();
  }

  public List<String> queryParameterValues(String name) {
    throw new UnsupportedOperationException();
  }

  public String queryParameterName(int index) {
    throw new UnsupportedOperationException();
  }

  public String queryParameterValue(int index) {
    throw new UnsupportedOperationException();
  }

  public String fragment() {
    throw new UnsupportedOperationException();
  }

  /**
   * Returns the URL that would be retrieved by following {@code link} from this URL.
   *
   * TODO: explain better.
   */
  public HttpUrl resolve(String link) {
    return parse(this, link);
  }

  public Builder newBuilder() {
    return new Builder(this);
  }

  /**
   * Returns a new {@code OkUrl} representing {@code url} if it is a well-formed HTTP or HTTPS URL,
   * or null if it isn't.
   */
  public static HttpUrl parse(String url) {
    return parse(null, url);
  }

  private static final int SCHEME_START = 1;
  private static final int SCHEME = 2;
  private static final int NO_SCHEME = 4;
  private static final int RELATIVE_OR_AUTHORITY = 5;
  private static final int RELATIVE = 6;
  private static final int RELATIVE_SLASH = 7;
  private static final int AUTHORITY_FIRST_SLASH = 8;
  private static final int AUTHORITY_SECOND_SLASH = 9;
  private static final int AUTHORITY_IGNORE_SLASHES = 10;
  private static final int AUTHORITY = 11;
  private static final int HOST = 13;
  private static final int PORT = 15;
  private static final int RELATIVE_PATH_START = 16;
  private static final int RELATIVE_PATH = 17;
  private static final int QUERY = 18;
  private static final int FRAGMENT = 19;

  private static HttpUrl parse(HttpUrl base, String input) {
    boolean atFlag = false;
    boolean boxFlag = false;
    int state = SCHEME_START;
    int[] codePoints = trimAndGetCodePoints(input);
    Builder result = new Builder();
    Buffer buffer = new Buffer();

    for (int i = 0, size = codePoints.length; i <= size; i++) {
      int c = i != size ? codePoints[i] : -1;

      switch (state) {
        case SCHEME_START:
          if (c >= 'a' && c <= 'z') {
            buffer.writeByte(c);
            state = SCHEME;
          } else if (c >= 'A' && c <= 'Z') {
            buffer.writeByte(c - ('A' - 'a'));
            state = SCHEME;
          } else {
            i--; // Unread 'c'.
            state = NO_SCHEME;
          }
          break;

        case SCHEME:
          if (c >= 'a' && c <= 'z' || (c >= '0' && c <= '9') || c == '+' || c == '-' || c == '.') {
            buffer.writeByte(c);
          } else if (c >= 'A' && c <= 'Z') {
            buffer.writeByte(c - ('A' - 'a'));
          } else if (c == ':') {
            result.scheme = buffer.readUtf8();
            if (!result.scheme.equals("http") && !result.scheme.equals("https")) {
              return null; // Input may be a valid URL, but it isn't supported by this class.
            }
            if (base != null && base.scheme.equals(result.scheme)) {
              state = RELATIVE_OR_AUTHORITY;
            } else {
              state = AUTHORITY_FIRST_SLASH;
            }
          } else {
            buffer.clear();
            state = NO_SCHEME;
            i = -1; // Start over.
          }
          break;

        case NO_SCHEME:
          if (base == null) {
            return null;
          }
          state = RELATIVE;
          i--; // Unread 'c'.
          break;

        case RELATIVE_OR_AUTHORITY:
          if (base == null) throw new IllegalArgumentException();
          if (c == '/' && input.regionMatches(false, i + 1, "/", 0, 1)) {
            i += 1; // Consume the second '/'.
            state = AUTHORITY_IGNORE_SLASHES;
          } else {
            i--; // Unread 'c'.
            state = RELATIVE;
          }
          break;

        case RELATIVE:
          if (base == null) throw new IllegalArgumentException();
          result.scheme = base.scheme;

          if (c == -1) {
            result.host = base.host;
            result.port = base.port;
            result.path.addAll(base.path);
            result.query = base.query != null ? new Buffer().writeUtf8(base.query) : null;
            // TODO: presumably we terminate here?
          } else if (c == '/' || c == '\\') {
            state = RELATIVE_SLASH;
          } else if (c == '?') {
            result.host = base.host;
            result.port = base.port;
            result.path.addAll(base.path);
            result.query = new Buffer();
            state = QUERY;
          } else if (c == '#') {
            result.host = base.host;
            result.port = base.port;
            result.path.addAll(base.path);
            result.query = base.query != null ? new Buffer().writeUtf8(base.query) : null;
            result.fragment = new Buffer();
            state = FRAGMENT;
          } else {
            result.host = base.host;
            result.port = base.port;
            result.path.addAll(base.path);
            result.path.remove(result.path.size() - 1); // TODO: can this be empty?
            i--; // Unread 'c'.
            state = RELATIVE_PATH;
          }
          break;

        case RELATIVE_SLASH:
          if (c == '/' || c == '\\') {
            state = AUTHORITY_IGNORE_SLASHES;
          } else {
            // set url’s host to base’s host and url’s port to base’s port.
            result.host = base.host;
            result.port = base.port;
            i--; // Unread 'c'.
            state = RELATIVE_PATH;
          }
          break;

        case AUTHORITY_FIRST_SLASH:
          if (c == '/') {
            state = AUTHORITY_SECOND_SLASH;
          } else {
            i--; // Unread 'c'.
            state = AUTHORITY_IGNORE_SLASHES;
          }
          break;

        case AUTHORITY_SECOND_SLASH:
          if (c == '/') {
            state = AUTHORITY_IGNORE_SLASHES;
          } else {
            i--; // Unread 'c'.
            state = AUTHORITY_IGNORE_SLASHES;
          }
          break;

        case AUTHORITY_IGNORE_SLASHES:
          if (c != '/' && c != '\\') {
            i--; // Unread 'c'.
            state = AUTHORITY;
          }
          break;

        case AUTHORITY:
          if (c == '@') {
            if (atFlag) {
              prepend(buffer, ByteString.encodeUtf8("%40"));
            }
            atFlag = true;

            try {
              while (!buffer.exhausted()) {
                int p = buffer.readUtf8CodePoint();
                if (p == '\t' || p == '\n' || p == '\r' || p != '%' && !isUrlCodePoint(p)) {
                  continue;
                }
                if (p == ':' && result.password == null) {
                  result.password = new Buffer();
                } else if (result.password != null) {
                  utf8PercentEncode(result.password, p, DEFAULT_ENCODE_SET);
                } else {
                  utf8PercentEncode(result.username, p, DEFAULT_ENCODE_SET);
                }
              }
            } catch (EOFException e) {
              buffer.clear(); // Strip partial code points.
            }
          } else if (c == -1 || c == '/' || c == '\\' || c == '?' || c == '#') {
            try {
              while (!buffer.exhausted()) {
                buffer.readUtf8CodePoint();
                i--; // Unread each codepoint in 'buffer'.
              }
              i--; // Unread 'c'.
              state = HOST;
            } catch (EOFException e) {
              throw new AssertionError();
            }
          } else {
            buffer.writeUtf8CodePoint(c);
          }
          break;

        case HOST:
          if (c == ':' && !boxFlag) {
            result.host = parseHost(buffer);
            if (result.host == null) return null;
            state = PORT;
          } else if (c == -1 || c == '/' || c == '\\' || c == '?' || c == '#') {
            i--; // Unread 'c'.
            result.host = parseHost(buffer);
            if (result.host == null) return null;
            state = RELATIVE_PATH_START;
          } else if (c != '\t' && c != '\n' && c != '\r') {
            if (c == '[') boxFlag = true;
            if (c == ']') boxFlag = false;
            buffer.writeUtf8CodePoint(c);
          }
          break;

        case PORT:
          if (c >= '0' || c <= '9') {
            buffer.writeUtf8CodePoint(c);
          } else if (c == -1 || c == '/' || c == '\\' || c == '?' || c == '#') {
            if (!buffer.exhausted()) {
              try {
                long portLong = buffer.readDecimalLong();
                if (portLong > Integer.MAX_VALUE) {
                  return null; // TODO: test this weird case. Should the limit be MAX_PORT ?
                }
                result.port = (int) portLong;
              } catch (NumberFormatException e) {
                // Too many digits in port.
                return null;
              }
            } else {
              // TODO: port can be an empty string.
            }
          } else if (c != '\t' && c != '\n' && c != '\r') {
            return null;
          }
          break;

        case RELATIVE_PATH_START:
          if (c != '/' && c != '\\') {
            i--; // Unread 'c'.
          }
          state = RELATIVE_PATH;
          break;

        case RELATIVE_PATH:
          if (c == -1 || c == '/' || c == '\\' || c == '?' || c == '#') {
            String lowercasePathSegment = buffer.clone().readByteString().toAsciiLowercase().utf8();
            if (lowercasePathSegment.equals("%2e")) {
              lowercasePathSegment = ".";
            } else if (lowercasePathSegment.equals(".%2e")
                || lowercasePathSegment.equals("%2e.")
                || lowercasePathSegment.equals("%2e%2e")) {
              lowercasePathSegment = "..";
            }

            if (lowercasePathSegment.equals("..")) {
              if (!result.path.isEmpty()) {
                result.path.remove(result.path.size() - 1);
              }
              if (c != '/' && c != '\\') {
                result.path.add("");
              }
            }

            if (lowercasePathSegment.equals(".") && c != '/' && c != '\\') {
              result.path.add("");
            }

            if (!lowercasePathSegment.equals(".")) {
              result.path.add(buffer.readUtf8());
            }

            buffer.clear();

            if (c == '?') {
              result.query = new Buffer();
              state = QUERY;
            } else if (c == '#') {
              result.fragment = new Buffer();
              state = FRAGMENT;
            }
          } else if (c != '\t' && c != '\r' && c != '\n') {
            if (c == '%'
                && (size < i + 2 || !isHex(codePoints[i + 1]) || !isHex(codePoints[i + 2]))) {
              // TODO: seems like this double-encodes '%'. What's up with that.
            }
            utf8PercentEncode(buffer, c, DEFAULT_ENCODE_SET);
          }
          break;

        case QUERY:
          if (c == -1 || c == '#') {
            while (buffer.exhausted()) {
              int b = buffer.readByte() & 0xff;
              if (b < 0x21 || b > 0x7e || b == '"' || b == '#' || b == '<' || b == '>' || b == '`') {
                buffer.writeByte('%');
                buffer.writeByte(DIGITS[b & 0xf]);
                buffer.writeByte(DIGITS[(b >>> 4) & 0xf]);
              } else {
                result.query.writeByte(b);
              }
            }
            if (c == '#') {
              result.fragment = new Buffer();
              state = FRAGMENT;
            }
          } else if (c != '\t' && c != '\r' && c != '\n') {
            if (c == '%'
                && (size < i + 2 || !isHex(codePoints[i + 1]) || !isHex(codePoints[i + 2]))) {
              // TODO: seems like this double-encodes '%'. What's up with that.
            }
            buffer.writeUtf8CodePoint(c);
          }
          break;

        case FRAGMENT:
          if (c != -1 && c != '\u0000' && c != '\t' && c != '\n' && c != '\r') {
            if (c == '%'
                && (size < i + 2 || !isHex(codePoints[i + 1]) || !isHex(codePoints[i + 2]))) {
              // TODO: seems like this double-encodes '%'. What's up with that.
            }
            result.fragment.writeUtf8CodePoint(c);
          }
          break;
      }
    }

    return result.build();
  }

  private static String parseHost(Buffer buffer) {
    return buffer.readUtf8(); // TODO.
  }

  private static String serializeHost(String host) {
    return host; // TODO
  }

  private static final byte[] DIGITS =
      { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };

  private static void utf8PercentEncode(Buffer buffer, int c, ByteString encodeSet) {
    boolean percentEncode = false;

    for (int i = 0; i < encodeSet.size(); i++) {
      if (encodeSet.getByte(i) == c) {
        percentEncode = true;
        break;
      }
    }

    if (!percentEncode) {
      buffer.writeUtf8CodePoint(c);
      return;
    }

    Buffer temp = new Buffer();
    temp.writeUtf8CodePoint(c);

    while (!temp.exhausted()) {
      int b = temp.readByte() & 0xff;
      buffer.writeByte('%');
      buffer.writeByte(DIGITS[b & 0xF]);
      buffer.writeByte(DIGITS[(b >>> 4) & 0xF]);
    }
  }

  private static boolean isUrlCodePoint(int c) {
    switch (c) {
      case '!':
      case '$':
      case '&':
      case '\'':
      case '(':
      case ')':
      case '*':
      case '+':
      case ',':
      case '-':
      case '.':
      case '/':
      case ':':
      case ';':
      case '=':
      case '?':
      case '@':
      case '_':
      case '~':
        return true;
    }

    if (c >= 'a' && c <= 'z') return true;
    if (c >= 'A' && c <= 'Z') return true;
    if (c >= '0' && c <= '9') return true;
    if (c >= 0x00a0 && c <= 0xd7ff) return true;
    if (c >= 0xe000 && c <= 0xfdcf) return true;
    if (c >= 0xfdf0 && c <= 0xfffd) return true;
    if (c >= 0x10000 && c <= 0x1fffd) return true;
    if (c >= 0x20000 && c <= 0x2fffd) return true;
    if (c >= 0x30000 && c <= 0x3fffd) return true;
    if (c >= 0x40000 && c <= 0x4fffd) return true;
    if (c >= 0x50000 && c <= 0x5fffd) return true;
    if (c >= 0x60000 && c <= 0x6fffd) return true;
    if (c >= 0x70000 && c <= 0x7fffd) return true;
    if (c >= 0x80000 && c <= 0x8fffd) return true;
    if (c >= 0x90000 && c <= 0x9fffd) return true;
    if (c >= 0xa0000 && c <= 0xafffd) return true;
    if (c >= 0xb0000 && c <= 0xbfffd) return true;
    if (c >= 0xc0000 && c <= 0xcfffd) return true;
    if (c >= 0xd0000 && c <= 0xdfffd) return true;
    if (c >= 0xe0000 && c <= 0xefffd) return true;
    if (c >= 0xf0000 && c <= 0xffffd) return true;
    if (c >= 0x100000 && c <= 0x10fffd) return true;
    return false;
  }

  private static boolean isHex(int c) {
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
  }

  /** Inserts {@code prefix} in front of {@code buffer}. */
  private static void prepend(Buffer buffer, ByteString prefix) {
    Buffer b = new Buffer();
    b.write(prefix);
    b.write(buffer, buffer.size());
    buffer.write(b, b.size());
  }

  private static int[] trimAndGetCodePoints(String input) {
    int[] codePoints = new int[input.length()];

    int codePointIndex = 0;
    for (int charIndex = 0, size = input.length(); charIndex < size; ) {
      int codePoint = input.codePointAt(charIndex);
      codePoints[codePointIndex++] = codePoint;
      charIndex += Character.charCount(codePoint); // TODO: what if it's overlong?
    }

    int startIndex = 0;
    for (; startIndex < codePoints.length; startIndex++) {
      int c = codePoints[startIndex];
      if (c != '\t' && c != '\n' && c != '\f' && c != '\r' && c != ' ') {
        break;
      }
    }

    int endIndex = codePointIndex;
    for (; endIndex > 0; endIndex--) {
      int c = codePoints[endIndex - 1];
      if (c != '\t' && c != '\n' && c != '\f' && c != '\r' && c != ' ') {
        break;
      }
    }

    int[] result = new int[endIndex - startIndex];
    System.arraycopy(codePoints, startIndex, result, 0, endIndex - startIndex);
    return result;
  }

  public static HttpUrl get(URL url) {
    return parse(url.toString());
  }

  public static HttpUrl get(URI uri) {
    return parse(uri.toString());
  }

  @Override public boolean equals(Object o) {
    return o instanceof HttpUrl && ((HttpUrl) o).url.equals(url);
  }

  @Override public int hashCode() {
    return url.hashCode();
  }

  @Override public String toString() {
    return url;
  }

  public static final class Builder {
    String scheme = "";
    Buffer username = new Buffer();
    Buffer password = null;
    String host = null;
    int port = -1;
    List<String> path = new ArrayList<>();
    Buffer query = null;
    Buffer fragment = null;

    public Builder() {
    }

    private Builder(HttpUrl url) {
    }

    public Builder scheme(String scheme) {
      throw new UnsupportedOperationException();
    }

    public Builder user(String user) {
      throw new UnsupportedOperationException();
    }

    public Builder encodedUser(String encodedUser) {
      throw new UnsupportedOperationException();
    }

    public Builder password(String password) {
      throw new UnsupportedOperationException();
    }

    public Builder encodedPassword(String encodedPassword) {
      throw new UnsupportedOperationException();
    }

    /**
     * @param host either a regular hostname, International Domain Name, IPv4 address, or IPv6
     *     address.
     */
    public Builder host(String host) {
      throw new UnsupportedOperationException();
    }

    public Builder port(int port) {
      throw new UnsupportedOperationException();
    }

    public Builder addPathSegment(String pathSegment) {
      if (pathSegment == null) throw new IllegalArgumentException("pathSegment == null");
      throw new UnsupportedOperationException();
    }

    public Builder addEncodedPathSegment(String encodedPathSegment) {
      if (encodedPathSegment == null) {
        throw new IllegalArgumentException("encodedPathSegment == null");
      }
      throw new UnsupportedOperationException();
    }

    public Builder encodedPath(String encodedPath) {
      throw new UnsupportedOperationException();
    }

    public Builder encodedQuery(String encodedQuery) {
      throw new UnsupportedOperationException();
    }

    /** Encodes the query parameter using UTF-8 and adds it to this URL's query string. */
    public Builder addQueryParameter(String name, String value) {
      if (name == null) throw new IllegalArgumentException("name == null");
      if (value == null) throw new IllegalArgumentException("value == null");
      throw new UnsupportedOperationException();
    }

    /** Adds the pre-encoded query parameter to this URL's query string. */
    public Builder addEncodedQueryParameter(String encodedName, String encodedValue) {
      if (encodedName == null) throw new IllegalArgumentException("encodedName == null");
      if (encodedValue == null) throw new IllegalArgumentException("encodedValue == null");
      throw new UnsupportedOperationException();
    }

    public Builder setQueryParameter(String name, String value) {
      if (name == null) throw new IllegalArgumentException("name == null");
      if (value == null) throw new IllegalArgumentException("value == null");
      throw new UnsupportedOperationException();
    }

    public Builder setEncodedQueryParameter(String encodedName, String encodedValue) {
      if (encodedName == null) throw new IllegalArgumentException("encodedName == null");
      if (encodedValue == null) throw new IllegalArgumentException("encodedValue == null");
      throw new UnsupportedOperationException();
    }

    public Builder removeAllQueryParameters(String name) {
      if (name == null) throw new IllegalArgumentException("name == null");
      throw new UnsupportedOperationException();
    }

    public Builder removeAllEncodedQueryParameters(String encodedName) {
      if (encodedName == null) throw new IllegalArgumentException("encodedName == null");
      throw new UnsupportedOperationException();
    }

    public Builder fragment(String fragment) {
      throw new UnsupportedOperationException();
    }

    public HttpUrl build() {
      StringBuilder url = new StringBuilder();
      url.append(scheme);
      url.append(':');
      url.append("//");
      if (username.size() > 0 || password != null) {
        url.append(username.clone().readUtf8());
        if (password != null) {
          url.append(password.clone().readUtf8());
        }
        url.append('@');
      }
      url.append(serializeHost(host));

      int defaultPort = defaultPort(scheme);
      int effectivePort = port != -1 ? port : defaultPort;
      if (effectivePort != defaultPort) {
        url.append(':');
        url.append(port);
      }

      if (path.isEmpty()) {
        throw new IllegalStateException(); // TODO.
      }
      for (String pathSegment : path) {
        url.append('/');
        url.append(pathSegment);
      }

      if (query != null) {
        url.append('?');
        url.append(query.clone().readUtf8());
      }
      if (fragment != null) {
        url.append('#');
        url.append(fragment.clone().readUtf8());
      }

      return new HttpUrl(
          scheme,
          username.clone().readUtf8(),
          password != null ? password.clone().readUtf8() : null,
          host,
          effectivePort,
          Util.immutableList(path),
          query != null ? query.clone().readUtf8() : null,
          fragment != null ? fragment.clone().readUtf8() : null,
          url.toString());
    }
  }
}
