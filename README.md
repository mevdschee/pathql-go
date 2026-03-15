# pathql-go

PathQL implementation in Go using Mux (see: [PathQL.org](https://pathql.org/)).

PathQL lets you write SQL queries that automatically produce nested JSON from
flat SQL result rows. The nesting structure is inferred from table aliases and
foreign key metadata, with optional SQL comment hints for overrides.

## How it works

You send a POST request to `/pathql` with a JSON body containing a SQL query and
optional parameters. The [pathsqlx](https://github.com/mevdschee/pathsqlx)
engine automatically determines the JSON structure by:

1. **Parsing the query** to identify tables, aliases, and joins.
2. **Detecting cardinality** using foreign key metadata (one-to-many vs
   many-to-one).
3. **Generating JSON paths** for each column based on the query structure.

If automatic inference isn't sufficient, you can use **PATH hints** (SQL
comments) to override the structure.

### PATH hints

PATH hints are SQL comments that override the automatic path inference for a
table alias:

```sql
-- PATH alias $.path
```

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
```

The `Listen` parameter is optional and defaults to `:8000` if not specified. You
can change it to bind to a different port or address (e.g., `":9000"` or
`"127.0.0.1:8000"`).

## Running

```sh
go build -o pathql-go
./pathql-go
```

The server starts on the configured listen address (default `:8000`) and exposes
a single endpoint: `POST /pathql`.

## Request format

```json
{
  "query": "SELECT id, content FROM posts WHERE id = :id",
  "params": { "id": 1 }
}
```

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
  "query": "SELECT posts.id, comments.id FROM posts LEFT JOIN comments ON post_id = posts.id WHERE posts.id <= 2 ORDER BY posts.id, comments.id -- PATH posts $.posts",
  "params": {}
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
  "query": "SELECT count(*) AS posts FROM posts p -- PATH p $",
  "params": {}
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
  "query": "SELECT count(*) AS posts FROM posts p -- PATH p $.statistics",
  "params": {}
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
  "query": "SELECT (SELECT count(*) FROM posts) as posts, (SELECT count(*) FROM comments) as comments -- PATH $ $.statistics",
  "params": {}
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
