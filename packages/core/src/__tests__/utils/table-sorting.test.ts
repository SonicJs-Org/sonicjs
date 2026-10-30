import { describe, it, expect } from 'vitest'
import { renderTable, TableData } from '../../templates/table.template'

describe('Table Sorting Functionality', () => {
  const sampleData: TableData = {
    tableId: 'test-table',
    columns: [
      { key: 'name', label: 'Name', sortable: true, sortType: 'string' },
      { key: 'age', label: 'Age', sortable: true, sortType: 'number' },
      { key: 'created', label: 'Created', sortable: true, sortType: 'date' },
      { key: 'active', label: 'Active', sortable: true, sortType: 'boolean' },
      { key: 'actions', label: 'Actions', sortable: false }
    ],
    rows: [
      { id: 1, name: 'John Doe', age: 30, created: '2023-01-01', active: true },
      { id: 2, name: 'Jane Smith', age: 25, created: '2023-02-01', active: false }
    ]
  }

  it('should render sortable table headers', () => {
    const html = renderTable(sampleData)
    
    // Check for sortable buttons
    expect(html).toContain('sort-btn')
    expect(html).toContain('data-column="name"')
    expect(html).toContain('data-sort-type="string"')
    expect(html).toContain('data-column="age"')
    expect(html).toContain('data-sort-type="number"')
    expect(html).toContain('data-column="created"')
    expect(html).toContain('data-sort-type="date"')
    expect(html).toContain('data-column="active"')
    expect(html).toContain('data-sort-type="boolean"')
  })

  it('should include sort icons', () => {
    const html = renderTable(sampleData)
    
    // Check for sort icons
    expect(html).toContain('sort-up')
    expect(html).toContain('sort-down')
    expect(html).toContain('opacity-30')
  })

  it('should include sorting JavaScript', () => {
    const html = renderTable(sampleData)
    
    // Check for sorting function
    expect(html).toContain('window.sortTable')
    expect(html).toContain('sortTable(')
  })

  it('should include table ID for sorting', () => {
    const html = renderTable(sampleData)
    
    // Check for table ID
    expect(html).toContain('id="test-table"')
  })

  it('should not make non-sortable columns sortable', () => {
    const html = renderTable(sampleData)
    
    // Actions column should not be sortable
    expect(html).not.toContain('data-column="actions"')
  })

  it('should handle empty data gracefully', () => {
    const emptyData: TableData = {
      tableId: 'empty-table',
      columns: [
        { key: 'name', label: 'Name', sortable: true, sortType: 'string' }
      ],
      rows: []
    }
    
    const html = renderTable(emptyData)
    expect(html).toContain('No data available')
  })

  it('should generate unique table ID when not provided', () => {
    const dataWithoutId: TableData = {
      columns: [
        { key: 'name', label: 'Name', sortable: true, sortType: 'string' }
      ],
      rows: [{ id: 1, name: 'Test' }]
    }
    
    const html = renderTable(dataWithoutId)
    expect(html).toMatch(/id="table-[a-z0-9]+"/)
  })
})