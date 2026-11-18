# SSLGuard Style Guide

## Component Library

SSLGuard uses a shared component system built with Jinja2 macros and CSS variables. **Always use the shared components.** Do not hand-write tables, badges, modals, or page headers.

---

## Importing Macros

At the top of every template:

```jinja2
{% extends "base.html" %}
{% import "_macros.html" as components %}
```

---

## Components

### 1. Page Header

Icon + Title + Optional Subtitle + Optional Action Button

```jinja2
{{ components.page_header(
    icon='speedometer2',
    title='Certificate Status Dashboard',
    subtitle='10 domains monitored',
    action_url=url_for('add_domain'),
    action_text='Add Domain',
    action_icon='plus-lg'
) }}
```

**Rules:**
- Use on every page for consistency
- Subtitle shows counts or static description
- Action button is optional (e.g., Reports has none)

---

### 2. Table Card

Wraps tables in a rounded card with shadow and hover states.

```jinja2
{{ components.table_card_start() }}
<table class="table table-hover">
    {# table content #}
</table>
{{ components.table_card_end() }}
```

**Rules:**
- Always wrap data tables in this component
- Do NOT add extra divs or inline styles
- Table gets `.table-hover` automatically

---

### 3. Row Actions

Primary button + "..." dropdown for secondary/destructive actions

```jinja2
{{ components.row_actions(
    primary_url=url_for('edit_domain', domain_id=domain.id),
    primary_text='Edit',
    primary_icon='pencil-square',
    primary_aria='Edit example.com',
    dropdown_items=[
        {'icon': 'clock-history', 'text': 'View History', 'form_action': url_for('scan_history', domain_id=domain.id)},
        {'divider': true},
        {'icon': 'trash', 'text': 'Delete Domain', 'variant': 'danger', 'modal': 'deleteModal' ~ domain.id}
    ],
    item_id=domain.id,
    item_name=domain.hostname
) }}
```

**Rules:**
- Primary action is always visible
- Dropdown contains secondary + destructive actions
- Use `disabled=true` for current user's own row
- Always provide `aria-label` for accessibility

---

### 4. Confirm Delete Modal

Reusable modal that names the item being deleted.

```jinja2
{{ components.confirm_delete_modal(
    modal_id='deleteModal' ~ domain.id,
    item_name=domain.hostname,
    item_type='domain',
    delete_url=url_for('delete_domain', domain_id=domain.id)
) }}
```

**Rules:**
- Use for all destructive actions (delete, disable)
- Modal ID must be unique per row (use item ID suffix)
- Shows item name in bold for confirmation

---

### 5. Toolbar (Search + Filters)

Search box + filter dropdowns + Clear button

```jinja2
{{ components.toolbar(
    search_placeholder='Search domain or team...',
    filters=[
        {'id': 'statusFilter', 'label': 'All Statuses', 'col_size': 3, 'options': [
            {'value': 'expired', 'text': 'Expired'},
            {'value': 'valid', 'text': 'Valid'}
        ]},
        {'id': 'ownerFilter', 'label': 'All Teams', 'col_size': 3, 'options': owner_options}
    ]
) }}
```

**Rules:**
- Use on all list pages (Dashboard, Domains, Users)
- Filters are optional, search box is always present
- Wire up with JavaScript (see examples in templates)

---

### 6. Date Formatter

Display: "Nov 18, 2026" with ISO tooltip

```jinja2
{{ components.format_date(domain.created_at, timezone='UTC') }}
```

**Rules:**
- Use everywhere dates are displayed
- Tooltip shows "2026-11-18 10:19 UTC"
- Timezone is configurable (default: UTC)

---

### 7. Status Badge

Consistent severity badges with icons

```jinja2
{{ components.status_badge(status='critical') }}
{{ components.status_badge(status='valid', label='Custom Label', icon='check', variant='success') }}
```

**Pre-configured statuses:**
- `expired` - Red, x-circle icon
- `critical` - Dark red, exclamation-triangle-fill icon
- `warning` - Amber, exclamation-triangle icon
- `valid` - Green, shield-check icon
- `error` - Gray, exclamation-circle icon

**Rules:**
- Status never conveyed by color alone (icon + text)
- Use pre-configured statuses when possible
- Custom badges: provide label, icon, variant

---

### 8. Empty State

No data message with optional CTA

```jinja2
{{ components.empty_state(
    message='No domains configured.',
    cta_url=url_for('add_domain'),
    cta_text='Add your first domain',
    icon='inbox'
) }}
```

**Rules:**
- Use when lists are empty
- CTA is optional
- Icon is customizable

---

### 9. Sortable Table Headers

```jinja2
{{ components.sortable_th('hostname', 'Hostname', icon='globe') }}
{{ components.sortable_th('days', 'Days Until Expiry', default_sort=true) }}
```

**Rules:**
- Only enable sorting where it makes sense
- One column can have `default_sort=true`
- Wire up JavaScript for sort functionality

---

### 10. Responsive Table Headers/Cells

Hide columns on mobile (<768px)

```jinja2
{# Header #}
{{ components.th_responsive('Added', icon='calendar', hide_mobile=true) }}

{# Cell #}
{{ components.td_responsive(components.format_date(domain.created_at), hide_mobile=true) }}
```

**Mobile column visibility:**
- **Dashboard**: Hide "Issued By" and "Last Scanned"
- **Domains**: Hide "Port" and "Added"  
- **Users**: Hide "Created"

**Rules:**
- Keep Domain/Username, Status, Actions visible
- Put hidden info in tooltips or secondary text where needed

---

## CSS Variables

Use CSS variables for colors, spacing, and styling. Never hardcode values.

```css
:root {
    --color-primary: #003366;
    --color-secondary: #0066cc;
    --color-success: #28a745;
    --color-warning: #f0ad4e;
    --color-danger: #dc3545;
    --color-muted: #6c757d;
    --color-critical: #d9534f;
    
    --card-border-radius: 8px;
    --card-shadow: 0 2px 8px rgba(0,0,0,0.1);
    --table-padding-y: 1rem;
    --transition-speed: 0.15s;
}
```

**Usage:**
```css
.my-component {
    background: var(--color-primary);
    border-radius: var(--card-border-radius);
    transition: all var(--transition-speed) ease;
}
```

---

## Rules

### ✅ DO:
- Use shared components for all UI elements
- Use CSS variables for colors and spacing
- Provide `aria-label` on icon-only buttons
- Add tooltips for additional context
- Format all dates with `format_date()` macro
- Wrap tables in `table_card_start/end()`
- Use `row_actions()` for action columns

### ❌ DON'T:
- Hand-write table HTML without macros
- Create one-off CSS classes for components
- Use inline styles
- Hardcode colors or spacing values
- Create duplicate modals (use shared `confirm_delete_modal`)
- Write custom badge HTML (use `status_badge()`)
- Forget mobile responsiveness (`hide_mobile=true`)

---

## Page Structure Template

```jinja2
{% extends "base.html" %}
{% import "_macros.html" as components %}

{% block title %}Page Title - SSLGuard{% endblock %}

{% block content %}

{# Page Header #}
{{ components.page_header(
    icon='icon-name',
    title='Page Title',
    subtitle='Optional subtitle or count',
    action_url=url_for('action_route'),
    action_text='Action Button',
    action_icon='plus-lg'
) }}

{# Empty State (if no data) #}
{% if not items %}
    {{ components.empty_state('No items found.', cta_url=url_for('add_item'), cta_text='Add first item') }}
{% else %}

{# Toolbar (optional) #}
{{ components.toolbar(search_placeholder='Search...', filters=[]) }}

{# Table #}
{{ components.table_card_start() }}
<table class="table table-hover">
    <thead class="table-dark">
        <tr>
            {{ components.sortable_th('column1', 'Column 1') }}
            <th>Column 2</th>
            {{ components.th_responsive('Column 3', hide_mobile=true) }}
            <th class="text-end">Actions</th>
        </tr>
    </thead>
    <tbody>
        {% for item in items %}
        <tr>
            <td>{{ item.name }}</td>
            <td>{{ components.status_badge(item.status) }}</td>
            {{ components.td_responsive(components.format_date(item.created), hide_mobile=true) }}
            <td class="actions-cell">
                {{ components.row_actions(
                    primary_url=url_for('edit_item', id=item.id),
                    dropdown_items=[
                        {'icon': 'trash', 'text': 'Delete', 'variant': 'danger', 'modal': 'deleteModal' ~ item.id}
                    ],
                    item_name=item.name
                ) }}
            </td>
        </tr>
        {# Modal outside loop for cleaner HTML #}
        {% endfor %}
    </tbody>
</table>
{{ components.table_card_end() }}

{# Modals #}
{% for item in items %}
    {{ components.confirm_delete_modal(
        modal_id='deleteModal' ~ item.id,
        item_name=item.name,
        item_type='item',
        delete_url=url_for('delete_item', id=item.id)
    ) }}
{% endfor %}

{% endif %}

{% endblock %}
```

---

## Accessibility Checklist

✅ All icon-only buttons have `aria-label`  
✅ Modals have proper ARIA attributes  
✅ Tooltips work with keyboard (Bootstrap tooltips)  
✅ Status conveyed by icon + text, not color alone  
✅ WCAG AA contrast ratios met  
✅ Focus states visible  
✅ Tables wrapped in `.table-responsive` for mobile  

---

## Questions?

Read the macro implementations in `templates/_macros.html` for parameter details and examples.
