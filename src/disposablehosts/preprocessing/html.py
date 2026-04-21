"""HTML data preprocessing and domain extraction."""

import html as html_module
from typing import List, Pattern, Union

from ..constants import HTML_GENERIC_RE


def preprocess_html(
    data: bytes,
    regex: Union[Pattern, List[Pattern], None] = None,
    encoding: str = "utf-8",
) -> List[str]:
    """Preprocess HTML data and extract domain strings.

    Args:
        data: Raw HTML bytes to process.
        regex: Regex pattern(s) for extraction. Uses HTML_GENERIC_RE if None.
        encoding: Character encoding to use for decoding.

    Returns:
        List of extracted domain strings.
    """
    raw = data.decode(encoding)
    html_re = regex if regex else HTML_GENERIC_RE

    if not isinstance(html_re, list):
        html_re = [html_re]

    html_ipt = raw
    html_list = []
    for html_re_item in html_re:
        html_list = html_re_item.findall(html_ipt)
        html_ipt = "\n".join(list(map(lambda o: o[0] if isinstance(o, tuple) else o, html_list)))

    return list(
        map(
            lambda opt: html_module.unescape(opt[0]) if isinstance(opt, tuple) else opt,
            html_list,
        )
    )
