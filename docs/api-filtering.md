# API Filtering Guide

SonicJS AI provides a powerful and flexible filtering system for querying content through the API. This guide covers all available filter operators and provides comprehensive examples.

## Table of Contents

- [Basic Usage](#basic-usage)
- [Filter Operators](#filter-operators)
- [AND/OR Logic](#andor-logic)
- [Sorting](#sorting)
- [Pagination](#pagination)
- [JSON Field Queries](#json-field-queries)
- [Complete Examples](#complete-examples)

## Basic Usage

Filters can be passed to the API in two equivalent forms:

1. **Bracket syntax** — `filter[field][operator]=value` (concise, recommended for simple queries)
2. **`where` parameter** — a JSON-encoded filter object (required for OR groups and complex logic)

Both forms can be combined in the same request; their conditions are combined with AND.

### Bracket Syntax

```bash
GET /api/content?filter[status][equals]=published
GET /api/content?filter[title][contains]=lyme&filter[status][equals]=published
```

When the operator is omitted, it defaults to `equals`:

```bash
GET /api/content?filter[slug]=about
```

### `where` Parameter (JSON)

```bash
GET /api/content?where={"and":[{"field":"status","operator":"equals","value":"published"}]}
```

URL-encoded:

```bash
GET /api/content?where=%7B%22and%22%3A%5B%7B%22field%22%3A%22status%22%2C%22operator%22%3A%22equals%22%2C%22value%22%3A%22published%22%7D%5D%7D
```

## Filter Operators

### equals

The value must be exactly equal.

```json
{
  "where": {
    "and": [
      {
        "field": "status",
        "operator": "equals",
        "value": "published"
      }
    ]
  }
}
```

**NULL handling:**
```json
{
  "where": {
    "and": [
      {
        "field": "deleted_at",
        "operator": "equals",
        "value": null
      }
    ]
  }
}
```

### not_equals

The query will return all documents where the value is not equal.

```json
{
  "where": {
    "and": [
      {
        "field": "status",
        "operator": "not_equals",
        "value": "draft"
      }
    ]
  }
}
```

### greater_than

For numeric or date-based fields.

```json
{
  "where": {
    "and": [
      {
        "field": "views",
        "operator": "greater_than",
        "value": 1000
      }
    ]
  }
}
```

**Date example:**
```json
{
  "where": {
    "and": [
      {
        "field": "created_at",
        "operator": "greater_than",
        "value": 1640995200000
      }
    ]
  }
}
```

### greater_than_equal

For numeric or date-based fields.

```json
{
  "where": {
    "and": [
      {
        "field": "price",
        "operator": "greater_than_equal",
        "value": 99.99
      }
    ]
  }
}
```

### less_than

For numeric or date-based fields.

```json
{
  "where": {
    "and": [
      {
        "field": "stock",
        "operator": "less_than",
        "value": 10
      }
    ]
  }
}
```

### less_than_equal

For numeric or date-based fields.

```json
{
  "where": {
    "and": [
      {
        "field": "priority",
        "operator": "less_than_equal",
        "value": 5
      }
    ]
  }
}
```

### like

Case-insensitive string search. If the value contains multiple words, all words must be present in any order.

```json
{
  "where": {
    "and": [
      {
        "field": "title",
        "operator": "like",
        "value": "getting started tutorial"
      }
    ]
  }
}
```

This will match:
- "Getting Started with Vue Tutorial"
- "Tutorial: Getting Started"
- "Started Getting Tutorial"

### contains

Must contain the value entered, case-insensitive. Simpler than `like` - just checks if the string is present.

```json
{
  "where": {
    "and": [
      {
        "field": "description",
        "operator": "contains",
        "value": "javascript"
      }
    ]
  }
}
```

### starts_with

The field value must begin with the provided value. Case-insensitive.

```json
{
  "where": {
    "and": [
      {
        "field": "title",
        "operator": "starts_with",
        "value": "How to"
      }
    ]
  }
}
```

### ends_with

The field value must end with the provided value. Case-insensitive.

```json
{
  "where": {
    "and": [
      {
        "field": "slug",
        "operator": "ends_with",
        "value": "-guide"
      }
    ]
  }
}
```

### in

The value must be found within the provided comma-delimited list of values.

**Array format:**
```json
{
  "where": {
    "and": [
      {
        "field": "status",
        "operator": "in",
        "value": ["published", "review", "scheduled"]
      }
    ]
  }
}
```

**Comma-delimited string:**
```json
{
  "where": {
    "and": [
      {
        "field": "category",
        "operator": "in",
        "value": "tech,science,education"
      }
    ]
  }
}
```

### not_in

The value must NOT be within the provided comma-delimited list of values.

```json
{
  "where": {
    "and": [
      {
        "field": "status",
        "operator": "not_in",
        "value": ["deleted", "archived", "spam"]
      }
    ]
  }
}
```

### all

The value must contain all values provided in the comma-delimited list. Useful for tags or multi-value fields.

```json
{
  "where": {
    "and": [
      {
        "field": "tags",
        "operator": "all",
        "value": "javascript,typescript,react"
      }
    ]
  }
}
```

This will only match documents that have ALL three tags.

### exists

Only return documents where the value either exists (true) or does not exist (false).

**Field exists:**
```json
{
  "where": {
    "and": [
      {
        "field": "thumbnail",
        "operator": "exists",
        "value": true
      }
    ]
  }
}
```

**Field does not exist:**
```json
{
  "where": {
    "and": [
      {
        "field": "thumbnail",
        "operator": "exists",
        "value": false
      }
    ]
  }
}
```

### near, within, intersects

**Note:** These spatial/geospatial operators are not currently supported in the SQLite/D1 implementation. For spatial queries, consider:
1. Using a spatial database extension
2. Implementing application-level filtering
3. Using a dedicated geospatial service

## AND/OR Logic

Filters support both AND and OR logic, which can be combined for complex queries.

### AND Logic

All conditions must be true.

```json
{
  "where": {
    "and": [
      {
        "field": "status",
        "operator": "equals",
        "value": "published"
      },
      {
        "field": "views",
        "operator": "greater_than",
        "value": 100
      },
      {
        "field": "category",
        "operator": "equals",
        "value": "tech"
      }
    ]
  }
}
```

### OR Logic

At least one condition must be true.

```json
{
  "where": {
    "or": [
      {
        "field": "status",
        "operator": "equals",
        "value": "published"
      },
      {
        "field": "status",
        "operator": "equals",
        "value": "review"
      }
    ]
  }
}
```

### Combined AND/OR

```json
{
  "where": {
    "and": [
      {
        "field": "category",
        "operator": "equals",
        "value": "tech"
      },
      {
        "field": "views",
        "operator": "greater_than",
        "value": 50
      }
    ],
    "or": [
      {
        "field": "featured",
        "operator": "equals",
        "value": true
      },
      {
        "field": "promoted",
        "operator": "equals",
        "value": true
      }
    ]
  }
}
```

This translates to: `(category = 'tech' AND views > 50) AND (featured = true OR promoted = true)`

## Sorting

Sort results by one or more fields.

### Single Field

```json
{
  "sort": [
    {
      "field": "created_at",
      "order": "desc"
    }
  ]
}
```

**URL:**
```bash
GET /api/content?sort=[{"field":"created_at","order":"desc"}]
```

### Multiple Fields

```json
{
  "sort": [
    {
      "field": "priority",
      "order": "desc"
    },
    {
      "field": "created_at",
      "order": "asc"
    }
  ]
}
```

## Pagination

Control the number of results and pagination.

### Limit

```bash
GET /api/content?limit=25
```

Maximum limit: 1000 results

### Offset

```bash
GET /api/content?limit=25&offset=50
```

This returns results 51-75.

### Combined with Filters

```bash
GET /api/content?where={"and":[{"field":"status","operator":"equals","value":"published"}]}&limit=10&offset=20
```

## JSON Field Queries

Query nested fields within JSON data using dot notation.

### Basic JSON Field

```json
{
  "where": {
    "and": [
      {
        "field": "data.author",
        "operator": "equals",
        "value": "John Doe"
      }
    ]
  }
}
```

### Nested JSON Field

```json
{
  "where": {
    "and": [
      {
        "field": "data.meta.seoTitle",
        "operator": "contains",
        "value": "Tutorial"
      }
    ]
  }
}
```

## Complete Examples

### Example 1: Blog Posts

Get all published tech blog posts with more than 100 views, sorted by views:

```bash
curl -X GET "https://your-api.com/api/content?where=%7B%22and%22%3A%5B%7B%22field%22%3A%22status%22%2C%22operator%22%3A%22equals%22%2C%22value%22%3A%22published%22%7D%2C%7B%22field%22%3A%22category%22%2C%22operator%22%3A%22equals%22%2C%22value%22%3A%22tech%22%7D%2C%7B%22field%22%3A%22views%22%2C%22operator%22%3A%22greater_than%22%2C%22value%22%3A100%7D%5D%7D&sort=%5B%7B%22field%22%3A%22views%22%2C%22order%22%3A%22desc%22%7D%5D&limit=10"
```

**Decoded filter:**
```json
{
  "where": {
    "and": [
      {
        "field": "status",
        "operator": "equals",
        "value": "published"
      },
      {
        "field": "category",
        "operator": "equals",
        "value": "tech"
      },
      {
        "field": "views",
        "operator": "greater_than",
        "value": 100
      }
    ]
  },
  "sort": [
    {
      "field": "views",
      "order": "desc"
    }
  ],
  "limit": 10
}
```

### Example 2: Product Search

Find products in specific categories, within a price range, with available stock:

```json
{
  "where": {
    "and": [
      {
        "field": "category",
        "operator": "in",
        "value": "electronics,computers,gaming"
      },
      {
        "field": "price",
        "operator": "greater_than_equal",
        "value": 50
      },
      {
        "field": "price",
        "operator": "less_than_equal",
        "value": 500
      },
      {
        "field": "stock",
        "operator": "greater_than",
        "value": 0
      }
    ]
  },
  "sort": [
    {
      "field": "price",
      "order": "asc"
    }
  ],
  "limit": 50
}
```

### Example 3: Recent Activity

Get recently created or updated content:

```json
{
  "where": {
    "or": [
      {
        "field": "created_at",
        "operator": "greater_than",
        "value": 1704067200000
      },
      {
        "field": "updated_at",
        "operator": "greater_than",
        "value": 1704067200000
      }
    ]
  },
  "sort": [
    {
      "field": "updated_at",
      "order": "desc"
    }
  ],
  "limit": 20
}
```

### Example 4: Tagged Content

Find content with specific tags:

```json
{
  "where": {
    "and": [
      {
        "field": "status",
        "operator": "equals",
        "value": "published"
      },
      {
        "field": "tags",
        "operator": "all",
        "value": "javascript,tutorial,beginner"
      }
    ]
  },
  "sort": [
    {
      "field": "created_at",
      "order": "desc"
    }
  ]
}
```

### Example 5: Complex Search

Multi-criteria search with fallback:

```json
{
  "where": {
    "and": [
      {
        "field": "status",
        "operator": "in",
        "value": ["published", "review"]
      }
    ],
    "or": [
      {
        "field": "title",
        "operator": "like",
        "value": "javascript react tutorial"
      },
      {
        "field": "description",
        "operator": "contains",
        "value": "react"
      },
      {
        "field": "tags",
        "operator": "contains",
        "value": "react"
      }
    ]
  },
  "sort": [
    {
      "field": "views",
      "order": "desc"
    },
    {
      "field": "created_at",
      "order": "desc"
    }
  ],
  "limit": 25
}
```

## Response Format

The API returns filtered results with metadata:

```json
{
  "data": [
    {
      "id": "abc123",
      "title": "Getting Started with React",
      "slug": "getting-started-react",
      "status": "published",
      "collectionId": "blog",
      "data": {},
      "created_at": 1704067200000,
      "updated_at": 1704153600000
    }
  ],
  "meta": {
    "count": 1,
    "timestamp": "2025-01-08T00:00:00.000Z",
    "filter": {
      "where": {},
      "limit": 50
    },
    "query": {
      "sql": "SELECT * FROM content WHERE status = ? LIMIT ?",
      "params": ["published", 50]
    },
    "cache": {
      "hit": false,
      "source": "database"
    },
    "timing": {
      "total": 45,
      "execution": 12,
      "unit": "ms"
    }
  }
}
```

## Best Practices

1. **Use specific filters**: The more specific your filters, the faster the query
2. **Limit results**: Always use `limit` to prevent large result sets
3. **Index fields**: Ensure frequently filtered fields are indexed in the database
4. **Cache results**: The API automatically caches results, but you can also cache on your end
5. **Combine operators wisely**: Use AND for narrowing results, OR for broadening
6. **Test queries**: Use the API console to test complex queries before implementing

## Error Handling

If a filter contains errors, the API will return a 400 error:

```json
{
  "error": "Invalid filter parameters",
  "details": [
    "'near' operator not supported in SQLite. Use spatial extension or application-level filtering."
  ]
}
```

## Performance Tips

- **Use indexed fields**: Filter on fields that have database indexes
- **Avoid LIKE on large text fields**: Use full-text search instead
- **Limit result sets**: Always specify a reasonable limit
- **Use pagination**: Don't fetch all results at once
- **Cache when possible**: Repeated queries with the same filters are cached automatically
