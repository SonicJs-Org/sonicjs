import {
  GraphQLSchema,
  GraphQLObjectType,
  GraphQLString,
  GraphQLInt,
  GraphQLBoolean,
  GraphQLNonNull,
} from 'graphql'
import { JSONScalar } from './scalars'
import { DocumentType, DocumentPageType } from './document-type'
import type { GraphqlResolverContext } from '../resolvers/context'
import { resolveDocuments, resolveDocument } from '../resolvers/queries'
import {
  resolveCreateDocument,
  resolveUpdateDocument,
  resolvePublishDocument,
  resolveUnpublishDocument,
  resolveDeleteDocument,
} from '../resolvers/mutations'

let _schema: GraphQLSchema | null = null

export function buildSchema(): GraphQLSchema {
  if (_schema) return _schema

  const QueryType = new GraphQLObjectType<unknown, GraphqlResolverContext>({
    name: 'Query',
    fields: {
      documents: {
        type: new GraphQLNonNull(DocumentPageType),
        description: 'List documents, optionally filtered by type and status.',
        args: {
          typeId:  { type: GraphQLString, description: 'Filter by document type id.' },
          status:  { type: GraphQLString, description: '"published" | "draft" | "all". Defaults to "published".' },
          limit:   { type: GraphQLInt,    description: 'Max results (1–200). Defaults to 50.' },
          cursor:  { type: GraphQLString, description: 'Opaque cursor from previous page.' },
          locale:  { type: GraphQLString, description: 'Filter by locale.' },
          sortDir: { type: GraphQLString, description: '"ASC" | "DESC". Defaults to "DESC".' },
        },
        resolve: (_root, args, ctx) => resolveDocuments(args, ctx),
      },
      document: {
        type: DocumentType,
        description: 'Fetch a single document by id.',
        args: {
          id: { type: new GraphQLNonNull(GraphQLString) },
        },
        resolve: (_root, args, ctx) => resolveDocument(args, ctx),
      },
    },
  })

  const MutationType = new GraphQLObjectType<unknown, GraphqlResolverContext>({
    name: 'Mutation',
    fields: {
      createDocument: {
        type: new GraphQLNonNull(DocumentType),
        description: 'Create a new document.',
        args: {
          typeId:          { type: new GraphQLNonNull(GraphQLString) },
          title:           { type: GraphQLString },
          slug:            { type: GraphQLString },
          data:            { type: new GraphQLNonNull(JSONScalar) },
          publishOnCreate: { type: GraphQLBoolean },
        },
        resolve: (_root, args, ctx) => resolveCreateDocument(args, ctx),
      },
      updateDocument: {
        type: new GraphQLNonNull(DocumentType),
        description: 'Save a draft update to an existing document.',
        args: {
          id:    { type: new GraphQLNonNull(GraphQLString) },
          title: { type: GraphQLString },
          slug:  { type: GraphQLString },
          data:  { type: JSONScalar },
        },
        resolve: (_root, args, ctx) => resolveUpdateDocument(args, ctx),
      },
      publishDocument: {
        type: new GraphQLNonNull(DocumentType),
        description: 'Publish a document by its row id.',
        args: {
          id: { type: new GraphQLNonNull(GraphQLString) },
        },
        resolve: (_root, args, ctx) => resolvePublishDocument(args, ctx),
      },
      unpublishDocument: {
        type: new GraphQLNonNull(DocumentType),
        description: 'Unpublish a document by its row id.',
        args: {
          id: { type: new GraphQLNonNull(GraphQLString) },
        },
        resolve: (_root, args, ctx) => resolveUnpublishDocument(args, ctx),
      },
      deleteDocument: {
        type: new GraphQLNonNull(GraphQLBoolean),
        description: 'Soft-delete a document by its row id.',
        args: {
          id: { type: new GraphQLNonNull(GraphQLString) },
        },
        resolve: (_root, args, ctx) => resolveDeleteDocument(args, ctx),
      },
    },
  })

  _schema = new GraphQLSchema({
    types: [JSONScalar],
    query: QueryType,
    mutation: MutationType,
  })

  return _schema
}

/** Reset the cached schema (useful in tests). */
export function resetSchema(): void {
  _schema = null
}
