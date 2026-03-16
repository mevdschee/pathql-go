# pathql-server

PathQL server implementation in Go using Mux (see: [PathQL.org](https://pathql.org/)).

PathQL lets you write SQL queries that automatically produce nested JSON from
flat SQL result rows. The nesting structure is inferred from table aliases and
foreign key metadata, with optional path hints for overrides.

## How it works

You send a POST request to `/pathql` with a JSON body containing a SQL query and
optional parameters. The [pathsqlx](https://github.com/mevdschee/pathsqlx)
engine automatically determines the JSON structure by:

1. **Parsing the query** to identify tables, aliases, and joins.
2. **Detecting cardinality** using foreign key metadata (one-to-many vs
   many-to-one).
3. **Generating JSON paths** for each column based on the query structure.

If automatic inference isn't sufficient, you can use **PATH hints** to override
the structure.

### PATH hints

PATH hints override the automatic path inference for table aliases. Provide
hints using the `paths` parameter in the request body:

```json
{
  "query": "SELECT ...",
  "params": {},
  "paths": { "alias": "$.path" }
}
```

PATH hint format:

- **`alias`** — the table alias (or `$` for queries without a real table)
- **`$.path`** — the JSON path for that table's columns
- If the path ends with `[]`, it's an array; otherwise, it's an object
- `$` alone means the root is a single object

## Configuration

Create a `config.ini` file in the project root:

```ini
Driver = "postgres"
DSN    = "host=localhost port=5432 user=your_user password=your_password dbname=your_database sslmode=disable"
Listen = ":8000"
Verbose = false
```

Configuration options:

- **`Driver`** — Database driver (e.g., `"postgres"`)
- **`DSN`** — Database connection string
- **`Listen`** — Server listen address (optional, defaults to `:8000`)
- **`Verbose`** — Enable verbose logging (optional, defaults to `false`). When
  enabled, logs timestamp, status code, response size, and latency for each
  request to stdout

## Running

```sh
go build -o pathql-server
./pathql-server
```

The server starts on the configured listen address (default `:8000`) and exposes
two endpoints:

- `POST /pathql` — Execute PathQL queries
- `GET /metrics` — View request metrics (status codes and latency distribution)

## Request format

```json
{
  "query": "SELECT id, content FROM posts WHERE id = :id",
  "params": { "id": 1 },
  "variables": { "dbname": "mydb" },
  "paths": { "posts": "$.posts" }
}
```

Request parameters:

- **`query`** (required) — SQL query string
- **`params`** (optional) — Named parameters for the query (must be an object,
  not an array)
- **`variables`** (optional) — DSN template variables for dynamic database
  connection
- **`paths`** (optional) — PATH hints to override automatic JSON path inference.
  Each key is a table alias, and each value is the JSON path (e.g.,
  `{"p": "$", "c": "$.comments[]"}`)

## Metrics

The `/metrics` endpoint returns JSON with request statistics:

```json
{
  "status_codes": {
    "200": 1523,
    "400": 12,
    "500": 3,
    "other": 0
  },
  "latency_ms": {
    "<1": 45,
    "<5": 892,
    "<10": 421,
    "<50": 123,
    "<100": 34,
    "<500": 7,
    "<1000": 1,
    "<5000": 0,
    "<10000": 0,
    ">=10000": 0
  }
}
```

Metrics are tracked using atomic 64-bit counters and are safe for concurrent
access.

## Examples

The examples below are based on a database with `posts`, `comments`, and
`categories` tables.

### Simple query — flat array

**Request:**

```json
{
  "query": "SELECT id, content FROM posts WHERE id = :id",
  "params": { "id": 1 }
}
```

**Response:**

```json
[{ "id": 1, "content": "blog started" }]
```

### Multiple records

**Request:**

```json
{
  "query": "SELECT id FROM posts WHERE id <= 2 ORDER BY id",
  "params": {}
}
```

**Response:**

```json
[{ "id": 1 }, { "id": 2 }]
```

### Join with automatic inference — posts with comments

Using table aliases (`p`, `c`), pathsqlx automatically detects the one-to-many
relationship via foreign keys and nests comments under each post:

**Request:**

```json
{
  "query": "SELECT p.id, c.id, c.message FROM posts p LEFT JOIN comments c ON c.post_id = p.id WHERE p.id <= 2 ORDER BY p.id, c.id",
  "params": {}
}
```

**Response:**

```json
[
  {
    "p": { "id": 1 },
    "c": [{ "id": 1, "message": "great!" }, { "id": 2, "message": "nice!" }]
  },
  {
    "p": { "id": 2 },
    "c": [{ "id": 3, "message": "interesting" }, { "id": 4, "message": "cool" }]
  }
]
```

### PATH hint — nested posts with comments

Using a PATH hint to control the root structure:

**Request:**

```json
{
  "query": "SELECT posts.id, comments.id FROM posts LEFT JOIN comments ON post_id = posts.id WHERE posts.id <= 2 ORDER BY posts.id, comments.id",
  "params": {},
  "paths": { "posts": "$.posts" }
}
```

**Response:**

```json
{
  "posts": [
    { "id": 1, "comments": [{ "id": 1 }, { "id": 2 }] },
    { "id": 2, "comments": [{ "id": 3 }, { "id": 4 }] }
  ]
}
```

### PATH hint — count as object

**Request:**

```json
{
  "query": "SELECT count(*) AS posts FROM posts p",
  "params": {},
  "paths": { "p": "$" }
}
```

**Response:**

```json
{ "posts": 2 }
```

### PATH hint — nested statistics object

**Request:**

```json
{
  "query": "SELECT count(*) AS posts FROM posts p",
  "params": {},
  "paths": { "p": "$.statistics" }
}
```

**Response:**

```json
{ "statistics": { "posts": 2 } }
```

### PATH hint — multiple scalar counts

**Request:**

```json
{
  "query": "SELECT (SELECT count(*) FROM posts) as posts, (SELECT count(*) FROM comments) as comments",
  "params": {},
  "paths": { "$": "$.statistics" }
}
```

**Response:**

```json
{ "statistics": { "posts": 2, "comments": 4 } }
```

### Group by

**Request:**

```json
{
  "query": "SELECT categories.name AS name, count(posts.id) AS post_count FROM posts, categories WHERE posts.category_id = categories.id GROUP BY categories.name ORDER BY categories.name",
  "params": {}
}
```

**Response:**

```json
[
  { "name": "announcement", "post_count": 2 },
  { "name": "article", "post_count": 1 }
]
```

## License

See [LICENSE](LICENSE).
