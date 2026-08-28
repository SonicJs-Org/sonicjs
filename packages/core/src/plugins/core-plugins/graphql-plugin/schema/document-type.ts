import {
  GraphQLObjectType,
  GraphQLString,
  GraphQLFloat,
  GraphQLBoolean,
  GraphQLNonNull,
  GraphQLList,
  GraphQLInt,
} from 'graphql'
import { JSONScalar } from './scalars'

export const DocumentType = new GraphQLObjectType({
  name: 'Document',
  description: 'A SonicJS document (any type).',
  fields: () => ({
    id:             { type: new GraphQLNonNull(GraphQLString) },
    rootId:         { type: new GraphQLNonNull(GraphQLString) },
    typeId:         { type: new GraphQLNonNull(GraphQLString) },
    title:          { type: GraphQLString },
    slug:           { type: GraphQLString },
    path:           { type: GraphQLString },
    status:         { type: new GraphQLNonNull(GraphQLString) },
    locale:         { type: new GraphQLNonNull(GraphQLString) },
    zone:           { type: GraphQLString },
    sortOrder:      { type: new GraphQLNonNull(GraphQLInt) },
    visible:        { type: new GraphQLNonNull(GraphQLBoolean) },
    isPublished:    { type: new GraphQLNonNull(GraphQLBoolean) },
    isCurrentDraft: { type: new GraphQLNonNull(GraphQLBoolean) },
    publishedAt:    { type: GraphQLFloat },
    scheduledAt:    { type: GraphQLFloat },
    expiresAt:      { type: GraphQLFloat },
    createdAt:      { type: new GraphQLNonNull(GraphQLFloat) },
    updatedAt:      { type: new GraphQLNonNull(GraphQLFloat) },
    versionNumber:  { type: new GraphQLNonNull(GraphQLInt) },
    tenantId:       { type: new GraphQLNonNull(GraphQLString) },
    ownerId:        { type: GraphQLString },
    createdBy:      { type: GraphQLString },
    updatedBy:      { type: GraphQLString },
    data:           { type: new GraphQLNonNull(JSONScalar), description: 'Document content payload.' },
    metadata:       { type: new GraphQLNonNull(JSONScalar), description: 'System/plugin metadata.' },
  }),
})

export const DocumentPageType = new GraphQLObjectType({
  name: 'DocumentPage',
  description: 'Paginated list of documents with keyset cursor.',
  fields: () => ({
    items:  { type: new GraphQLNonNull(new GraphQLList(new GraphQLNonNull(DocumentType))) },
    cursor: { type: GraphQLString, description: 'Opaque cursor for next page. Pass as `cursor` arg.' },
  }),
})
