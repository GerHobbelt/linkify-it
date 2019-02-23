'use strict';


module.exports = function (opts) {
  var re = {};

  // Use direct extract instead of `regenerate` to reduse browserified size
  re.src_Any = require('uc.micro/properties/Any/regex').source;
  re.src_Cc  = require('uc.micro/categories/Cc/regex').source;
  re.src_Z   = require('uc.micro/categories/Z/regex').source;
  re.src_P   = require('uc.micro/categories/P/regex').source;

  // \p{\Z\P\Cc\CF} (white spaces + control + format + punctuation)
  re.src_ZPCc = [ re.src_Z, re.src_P, re.src_Cc ].join('|');

  // \p{\Z\Cc} (white spaces + control)
  re.src_ZCc = [ re.src_Z, re.src_Cc ].join('|');

  // Experimental. List of chars, completely prohibited in links
  // because can separate it from other part of text
  var text_separators = '[><\uff5c]';

  // All possible word characters (everything without punctuation, spaces & controls)
  // Defined via punctuation & spaces to save space
  // Should be something like \p{\L\N\S\M} (\w but without `_`)
  re.src_pseudo_letter       = '(?:(?!' + text_separators + '|' + re.src_ZPCc + ')' + re.src_Any + ')';
  // The same as above but without [0-9]
  // var src_pseudo_letter_non_d = '(?:(?![0-9]|' + src_ZPCc + ')' + src_Any + ')';

  ////////////////////////////////////////////////////////////////////////////////

  re.src_ip4 =

    '(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)';

  re.src_ip6_hexpart =

    '(?:[a-fA-F0-9]{1,4})';

  re.src_ip6 =

    '(?:' +
    // preferred form:
    '(?:' + re.src_ip6_hexpart + ':){7}' + re.src_ip6_hexpart + '|' +
    // any of the compressed forms:
    '::' + '(?:' + re.src_ip6_hexpart + ':){0,6}' + re.src_ip6_hexpart + '|' +
    '(?:' + re.src_ip6_hexpart + ':){1}:' + '(?:' + re.src_ip6_hexpart + ':){0,5}' + re.src_ip6_hexpart + '|' +
    '(?:' + re.src_ip6_hexpart + ':){2}:' + '(?:' + re.src_ip6_hexpart + ':){0,4}' + re.src_ip6_hexpart + '|' +
    '(?:' + re.src_ip6_hexpart + ':){3}:' + '(?:' + re.src_ip6_hexpart + ':){0,3}' + re.src_ip6_hexpart + '|' +
    '(?:' + re.src_ip6_hexpart + ':){4}:' + '(?:' + re.src_ip6_hexpart + ':){0,2}' + re.src_ip6_hexpart + '|' +
    '(?:' + re.src_ip6_hexpart + ':){5}:' + '(?:' + re.src_ip6_hexpart + ':)?' + re.src_ip6_hexpart + '|' +
    '(?:' + re.src_ip6_hexpart + ':){6}:' + re.src_ip6_hexpart + '|' +
    // preferred form for IP4 wrap:
    '(?:' + re.src_ip6_hexpart + ':){6}' + re.src_ip4 + '|' +
    // any of the compressed forms for IP4 wrapping:
    '::' + '(?:' + re.src_ip6_hexpart + ':){0,5}' + re.src_ip4 + '|' +
    '(?:' + re.src_ip6_hexpart + ':){1}:' + '(?:' + re.src_ip6_hexpart + ':){0,4}' + re.src_ip4 + '|' +
    '(?:' + re.src_ip6_hexpart + ':){2}:' + '(?:' + re.src_ip6_hexpart + ':){0,3}' + re.src_ip4 + '|' +
    '(?:' + re.src_ip6_hexpart + ':){3}:' + '(?:' + re.src_ip6_hexpart + ':){0,2}' + re.src_ip4 + '|' +
    '(?:' + re.src_ip6_hexpart + ':){4}:' + '(?:' + re.src_ip6_hexpart + ':)?' + re.src_ip4 + '|' +
    '(?:' + re.src_ip6_hexpart + ':){5}:' + re.src_ip4 +
    ')';

  // Prohibit any of "@/[]()" in user/pass to avoid wrong domain fetch.
  re.src_auth = '(?:(?:(?!' + re.src_ZCc + '|' + text_separators + '|[@/\\[\\]()]).)+@)?';

  re.src_port =

    '(?::(?:6(?:[0-4]\\d{3}|5(?:[0-4]\\d{2}|5(?:[0-2]\\d|3[0-5])))|[1-5]?\\d{1,4}))?';

  re.src_host_terminator =

    '(?=$|' + text_separators + '|' + re.src_ZPCc + ')' +
    '(?!-|_|:\\d|\\.-|\\.(?!$|' + re.src_ZPCc + '|' + text_separators + '))';

  re.src_path =

    '(' +
      '[/?#]' +
        '(?:' +
          '(?!' + re.src_ZCc + '|' + text_separators + '|[()[\\]{}.,;:*&%"\'?!\\-]).|' +
          '\\[(?:(?!' + re.src_ZCc + '|' + text_separators + '|\\]).)*\\]|' +
          // // support up to 3 levels of braces nesting...
          // // anything further is subject to quickly deminishing returns
          // // (the 3rd level is already rather rediculous):
          // '\\((?:(?:(?!' + re.src_ZCc + '|[()]).)*|(?:\\((?:(?:(?!' + re.src_ZCc + '|[()]).)*|' +
          //               '(?:\\((?:(?!' + re.src_ZCc + '|[()]).)*\\)))*\\)))*\\)|' +
          //
          // ^^^--- it turns out that the above regex is *quite* slow for any URI with
          // unmatched braces, while alternative regexes for 2 levels and up also turn out to be
          // pretty prohibitive in performance cost, hence we simplify it all down to this
          // "eat everything until you hit a closing brace, **aggressively**" regex below,
          // which supports *any* level of nested braces, whil being very lenient on
          // the 'matching' of the inner braces sets:
          '\\((?:(?!' + re.src_ZCc + '|' + text_separators + ').)*\\)|' +
          '\\{(?:(?!' + re.src_ZCc + '|' + text_separators + '|[}]).)*\\}|' +
          '\\"(?:(?!' + re.src_ZCc + '|' + text_separators + '|["]).)+\\"|' +
          "\\'(?:(?!" + re.src_ZCc + '|' + text_separators + "|[']).)+\\'|" +
          "\\'(?=" + re.src_pseudo_letter + '|[-])|' +  // allow `I'm_king` if no pair found
          // github has `...` in commit range links. Restrict to
          // - english
          // - percent-encoded
          // - parts of file path
          // until more examples found:
          '\\.{1,3}(?:[a-zA-Z0-9_/]|%[a-fA-F0-9])|' +
          '\\.(?!' + re.src_ZCc + '|' + text_separators + '|[.]|$)|' +
          (opts && opts['---'] ?
            '\\-(?!--)|'            // `---` => long dash, terminate
            :
            '\\-+|'
          ) +
          // allow `,,,` in paths, but uri MUST NOT end with a `,`
          '\\,+(?!' + re.src_ZCc + '|' + text_separators + '|[,]|$)|' +
          // allow `&&` in paths and at end of uri (as query part sentinel)
          '&+(?!' + re.src_ZCc + '|' + text_separators + '|[&])|' +
          // percent-encoded
          '%[a-fA-F0-9]+|' +
          // uri path MUST NOT end with any of these: [:;!?]
          ':(?!' + re.src_ZCc + '|' + text_separators + '|[:]|$)|' +
          ';(?!' + re.src_ZCc + '|' + text_separators + '|[;]|$)|' +
          '\\!(?!' + re.src_ZCc + '|' + text_separators + '|[!]|$)|' +
          '\\?(?!' + re.src_ZCc + '|' + text_separators + '|[?]|$)' +
        ')+' +
      '|\\/' +
    ')?';

  // now make sure we didn't gobble too much:
  // some characters are not acceptable at the end
  // of a URL, e.g. dot `.`:
  re.src_not_allowed_at_end_of_url =

    '[;:.,!?]';

  re.src_email_name =

    '[\\-;:&=\\+\\$,\\"\\.a-zA-Z0-9_]+';

  re.src_get_params =

    '((?:[?&]' +
    '(?:(?!' + re.src_ZCc + '|' + text_separators + '|[&=]).)+' +
    '(?:=(?:(?!' + re.src_ZCc + '|' + text_separators + '|[&=]).)*)?' +
    ')+|)';

  re.src_xn =

    'xn--[a-z0-9\\-]{1,59}';

  // More to read about domain names
  // http://serverfault.com/questions/638260/

  re.src_domain_root =

    // Allow letters & digits (http://test1)
    '(?:' +
      re.src_xn +
      '|' +
      re.src_pseudo_letter + '{1,63}' +
    ')';

  re.src_domain =

    '(?:' +
      re.src_xn +
      '|' +
      '(?:' + re.src_pseudo_letter + ')' +
      '|' +
      '(?:' + re.src_pseudo_letter + '(?:-|' + re.src_pseudo_letter + '){0,61}' + re.src_pseudo_letter + ')' +
    ')';

  re.src_host =

    '(?:' +
    // Don't need IP4 check, because digits are already allowed in normal domain names
    //   re.src_ip4 +
    // '|' +
      '(?:\\[' + re.src_ip6 + '\\])' +
    // '|' +
    //   'localhost' +
    '|' +
      // Don't allow single-level domains, because of false positives like '//test'
      // with code comments
      '(?:(?:(?:' + re.src_domain + ')\\.)+' + re.src_domain_root + ')' +
    ')';

  re.src_host_or_localhosts =

    '(?:' +
    // Don't need IP4 check, because digits are already allowed in normal domain names
    //   re.src_ip4 +
    // '|' +
      '(?:\\[' + re.src_ip6 + '\\])' +
    '|' +
      '(?:(?:(?:' + re.src_domain + ')\\.)*' + re.src_domain/*_root*/ + ')' +
    ')';

  re.tpl_host_fuzzy =

    '(?:' +
      re.src_ip4 +
    '|' +
      '(?:\\[' + re.src_ip6 + '\\])' +
    // '|' +
    //   'localhost' +
    '|' +
      // Don't allow single-level domains, because of false positives like '//test'
      // with code comments
      '(?:(?:(?:' + re.src_domain + ')\\.)+(?:%TLDS%))' +
    ')';

  re.tpl_host_no_ip_fuzzy =

    //   'localhost' +
    // '|' +
      // Don't allow single-level domains, because of false positives like '//test'
      // with code comments
      '(?:(?:(?:' + re.src_domain + ')\\.)+(?:%TLDS%))';

  re.src_host_strict =

    re.src_host + re.src_host_terminator;

  re.tpl_host_fuzzy_strict =

    re.tpl_host_fuzzy + re.src_host_terminator;

  re.src_host_port_strict =

    re.src_host + re.src_port + re.src_host_terminator;

  re.tpl_host_port_fuzzy_strict =

    re.tpl_host_fuzzy + re.src_port + re.src_host_terminator;

  re.tpl_host_port_no_ip_fuzzy_strict =

    re.tpl_host_no_ip_fuzzy + re.src_port + re.src_host_terminator;

  re.src_telephone =

    '(?:[+][0-9]+[ -]?)?(?:(?:[0-9]+|\\([0-9]+\\))[ -]?)*[0-9]+';

  re.src_telephone_strict =

    re.src_telephone + re.src_host_terminator;

  re.src_open_brackets =

    '[\\(\\[{]';

  ////////////////////////////////////////////////////////////////////////////////
  // Main rules

  // Rude test fuzzy links by host, for quick deny
  re.tpl_host_fuzzy_test =

    'localhost|www\\.|' +
    '\\.\\d{1,3}\\.|\\[::[a-fA-F0-9]{1,4}|\\[[a-fA-F0-9]{1,4}:[a-fA-F0-9]{1,4}|' +
    '(?:\\.(?:%TLDS%)(?:' + re.src_ZPCc + '|>|$))';

  re.tpl_email_fuzzy =

      '(^|' + text_separators + '|' + re.src_open_brackets + '|' + re.src_ZCc + ')(' + re.src_email_name + '@' +
      re.tpl_host_fuzzy_strict + re.src_get_params + ')';

  re.tpl_link_fuzzy =
      // Fuzzy link can't be prepended with .:/\- and non punctuation.
      // but can start with > (markdown blockquote)
      '(^|(?![.:/\\-_@])(?:[$+=^`|]|' + text_separators + '|' + re.src_ZPCc + '))' +
      '((?![$+=^`|]|' + text_separators + ')' + re.tpl_host_port_fuzzy_strict + re.src_path + ')';

  re.tpl_link_no_ip_fuzzy =
      // Fuzzy link can't be prepended with .:/\- and non punctuation.
      // but can start with > (markdown blockquote)
      '(^|(?![.:/\\-_@])(?:[$+=^`|]|' + text_separators + '|' + re.src_ZPCc + '))' +
      '((?![$+=^`|]|' + text_separators + ')' + re.tpl_host_port_no_ip_fuzzy_strict + re.src_path + ')';

  return re;
};
