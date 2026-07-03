const db = require('../db.js');
async function check() {
  const items = await db.all('SELECT id, name, length(image_url) as len FROM items WHERE image_url IS NOT NULL');
  console.log(items);
  // Clear huge images for the user to make the app usable
  for (let item of items) {
    if (item.len > 100000) {
      console.log(`Clearing huge image for ${item.id} (${item.len} bytes)`);
      await db.run('UPDATE items SET image_url = NULL WHERE id = ?', [item.id]);
    }
  }
}
check();
