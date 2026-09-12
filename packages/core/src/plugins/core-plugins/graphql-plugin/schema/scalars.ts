import { GraphQLScalarType, Kind, type ValueNode } from 'graphql'

function parseLiteralValue(ast: ValueNode): unknown {
  switch (ast.kind) {
    case Kind.STRING:
      try { return JSON.parse(ast.value) } catch { return ast.value }
    case Kind.INT:
      return parseInt(ast.value, 10)
    case Kind.FLOAT:
      return parseFloat(ast.value)
    case Kind.BOOLEAN:
      return ast.value
    case Kind.NULL:
      return null
    case Kind.OBJECT: {
      const obj: Record<string, unknown> = {}
      for (const field of ast.fields) {
        obj[field.name.value] = parseLiteralValue(field.value)
      }
      return obj
    }
    case Kind.LIST:
      return ast.values.map(v => parseLiteralValue(v))
    default:
      return null
  }
}

export const JSONScalar: GraphQLScalarType = new GraphQLScalarType({
  name: 'JSON',
  description: 'Arbitrary JSON value',
  serialize(value: unknown): unknown {
    return value
  },
  parseValue(value: unknown): unknown {
    return value
  },
  parseLiteral(ast: ValueNode): unknown {
    return parseLiteralValue(ast)
  },
})
