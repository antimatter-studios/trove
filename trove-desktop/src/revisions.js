export function linkedDatabases(database, databases) {
  const uuid = database.troveUuid?.trim().toLowerCase();
  return uuid ? databases.filter((candidate) => candidate.id !== database.id && !candidate.locked && candidate.troveUuid?.trim().toLowerCase() === uuid) : [];
}

export function compareEntries(left, right, includeMatching = false) {
  const leftById = new Map(left.map((entry) => [entry.id, entry]));
  const rightById = new Map(right.map((entry) => [entry.id, entry]));
  return [...new Set([...leftById.keys(), ...rightById.keys()])].map((id) => {
    const leftEntry = leftById.get(id);
    const rightEntry = rightById.get(id);
    const status = !leftEntry ? 'Only in linked database' : !rightEntry ? 'Only in this database' : leftEntry.token === rightEntry.token ? 'Matching' : 'Different';
    return { id, left: leftEntry, right: rightEntry, title: (leftEntry || rightEntry).title, status };
  }).filter((entry) => includeMatching || entry.status !== 'Matching').sort((leftEntry, rightEntry) => leftEntry.title.localeCompare(rightEntry.title) || leftEntry.id.localeCompare(rightEntry.id));
}

function revisionValues(revision) {
  const values = new Map();
  for (const field of revision?.fields || []) values.set('field:' + field.name, { label: field.name, value: field.value, protected: field.protected });
  for (const attachment of revision?.attachments || []) values.set('attachment:' + attachment.name, { label: 'Attachment: ' + attachment.name, value: `${attachment.size} bytes · ${attachment.digest}` });
  for (const [name, value] of Object.entries(revision?.properties || {})) values.set('property:' + name, { label: name, value, protected: name.startsWith('Custom data:') || name === 'Auto-type' });
  return values;
}

export function revisionDiff(left, right) {
  const leftValues = revisionValues(left);
  const rightValues = revisionValues(right);
  return [...new Set([...leftValues.keys(), ...rightValues.keys()])].map((key) => {
    const leftValue = leftValues.get(key);
    const rightValue = rightValues.get(key);
    return {
      key, label: (leftValue || rightValue).label,
      left: leftValue?.value, right: rightValue?.value,
      protected: !!(leftValue?.protected || rightValue?.protected),
      changed: leftValue?.value !== rightValue?.value || !!leftValue?.protected !== !!rightValue?.protected,
    };
  });
}
