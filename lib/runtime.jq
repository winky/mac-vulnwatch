# lib/runtime.jq
# Maps a tool installed by a version manager to an endoflife.date product.
#
# Used twice: by the fetch, to know which products' releases to download, and by the parse,
# to match versions against them. Both must agree, hence one definition.
#
# $index is endoflife.date's product list: [{"name": "nodejs", "aliases": ["node"]}, ...].

# Tool names that are neither a product name nor one of its aliases.
def product_overrides:
  {"kubectl": "kubernetes"};

def product_for($name; $index):
  product_overrides[$name]
  // ([$index[] | select(.name == $name or ((.aliases // []) | index($name)))][0].name);

# mise can name a tool by backend, e.g. aqua:hashicorp/terraform or core:node. What follows the
# backend and the last slash is the name endoflife.date would know.
def tool_name:
  sub("^[a-z0-9-]+:"; "") | split("/") | last;

# {manager, tool, version} -> the same with "product" and a normalised "version" added, plus
# "eol_only" when the version cannot be compared with endoflife.date's. Nothing comes out for
# a tool with no product, or a version that is not a version (system, latest, ref:..., path:...).
def resolve($index):
  . as $install
  | ($install.version | ltrimstr("v")) as $raw
  | ($install.tool | tool_name) as $tool
  | if $tool == "java" then
      # asdf-java names versions <vendor>-<version>, e.g. temurin-21.0.2+13.0.LTS,
      # corretto-21.0.2.13.1, zulu-21.32.17. The vendor is the product. Only end of life is
      # judged: Zulu numbers its builds independently of the JDK, so comparing patch versions
      # would report updates that are not there.
      ($raw | capture("^(?<vendor>[a-z][a-z-]*?)-(?<version>[0-9].*)$")?) as $parts
      | select($parts != null)
      | product_for($parts.vendor; $index) as $product
      | select($product != null)
      | $install + {product: $product, version: ($parts.version | sub("\\+.*$"; "")), eol_only: true}
    else
      select($raw | test("^[0-9]"))
      | product_for($tool; $index) as $product
      | select($product != null)
      | $install + {product: $product, version: ($raw | sub("\\+.*$"; "")), eol_only: false}
    end;
