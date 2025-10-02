from PyQt6.QtWidgets import QApplication, QGraphicsView, QGraphicsScene, QGraphicsEllipseItem, QGraphicsRectItem, QGraphicsLineItem, QGraphicsTextItem, QGraphicsItem, QGraphicsPathItem
from PyQt6.QtGui import QPen, QBrush, QColor, QPixmap, QPainter, QPainterPath, QPolygonF
from PyQt6.QtCore import Qt, QPointF, QRectF
import math

class DraggableNode(QGraphicsEllipseItem):
    def __init__(self, x, y, radius, color, node_id, node_type):
        super().__init__(-radius, -radius, 2*radius, 2*radius)
        self.setBrush(QBrush(QColor(color)))
        self.setPen(QPen(Qt.GlobalColor.black, 2))
        self.setPos(x, y)

        # Remove movable flag
        self.setFlags(QGraphicsItem.GraphicsItemFlag.ItemSendsScenePositionChanges)

        self.node_id = node_id
        self.node_type = node_type
        self.radius = radius
        self.click_callback = None
        self._dragging = False

        # Label
        self.text = QGraphicsTextItem(str(node_id))
        self.text.setDefaultTextColor(Qt.GlobalColor.white)
        self.text.setParentItem(self)
        self.text.setPos(-radius/2, -radius/2)

    def mousePressEvent(self, event):
        if event.button() == Qt.MouseButton.LeftButton and self.click_callback:
            self.click_callback(self.node_id)
            event.accept()
        elif event.button() == Qt.MouseButton.RightButton:
            self._dragging = True
            self._drag_start_pos = event.scenePos() - self.scenePos()
            event.accept()
        else:
            super().mousePressEvent(event)

    def mouseMoveEvent(self, event):
        if self._dragging:
            new_pos = event.scenePos() - self._drag_start_pos
            self.setPos(new_pos)
            event.accept()
        else:
            super().mouseMoveEvent(event)

    def mouseReleaseEvent(self, event):
        if event.button() == Qt.MouseButton.RightButton:
            self._dragging = False
            event.accept()
        else:
            super().mouseReleaseEvent(event)

    def get_radius(self):
        return self.radius

    def set_click_callback(self, callback):
        """Set a callback function to be called when node is clicked"""
        self.click_callback = callback

    def itemChange(self, change, value):
        if change == QGraphicsItem.GraphicsItemChange.ItemPositionHasChanged:
            for arrow in getattr(self, 'arrows', []):
                arrow.update_position()
        return super().itemChange(change, value)


class RectNode(QGraphicsRectItem):
    def __init__(self, x, y, width, height, color, node_id, node_type):
        super().__init__(-width/2, -height/2, width, height)
        self.setBrush(QBrush(QColor(color)))
        self.setPen(QPen(Qt.GlobalColor.black, 2))
        self.setPos(x, y)

        # Remove movable flag
        self.setFlags(QGraphicsItem.GraphicsItemFlag.ItemSendsScenePositionChanges)

        self.node_id = node_id
        self.node_type = node_type
        self.width = width
        self.height = height
        self.click_callback = None
        self._dragging = False

        # Label
        self.text = QGraphicsTextItem(str(node_id))
        self.text.setDefaultTextColor(Qt.GlobalColor.white)
        self.text.setParentItem(self)
        self.text.setPos(-width/4, -height/4)

    def mousePressEvent(self, event):
        if event.button() == Qt.MouseButton.LeftButton and self.click_callback:
            self.click_callback(self.node_id)
            event.accept()
        elif event.button() == Qt.MouseButton.RightButton:
            self._dragging = True
            self._drag_start_pos = event.scenePos() - self.scenePos()
            event.accept()
        else:
            super().mousePressEvent(event)

    def mouseMoveEvent(self, event):
        if self._dragging:
            new_pos = event.scenePos() - self._drag_start_pos
            self.setPos(new_pos)
            event.accept()
        else:
            super().mouseMoveEvent(event)

    def mouseReleaseEvent(self, event):
        if event.button() == Qt.MouseButton.RightButton:
            self._dragging = False
            event.accept()
        else:
            super().mouseReleaseEvent(event)

    def get_radius(self):
        # Return diagonal distance for rectangle
        return math.sqrt((self.width/2)**2 + (self.height/2)**2)

    def set_click_callback(self, callback):
        """Set a callback function to be called when node is clicked"""
        self.click_callback = callback

    def itemChange(self, change, value):
        if change == QGraphicsItem.GraphicsItemChange.ItemPositionHasChanged:
            for arrow in getattr(self, 'arrows', []):
                arrow.update_position()
        return super().itemChange(change, value)


class BidirectionalArrow(QGraphicsPathItem):
    def __init__(self, start_node, end_node, color, scene=None):
        super().__init__()
        self.start_node = start_node
        self.end_node = end_node
        self.arrow_size = 12

        pen = QPen(QColor(color), 3)
        pen.setCapStyle(Qt.PenCapStyle.RoundCap)
        pen.setJoinStyle(Qt.PenJoinStyle.RoundJoin)
        self.setPen(pen)
        self.setBrush(QBrush(QColor(color)))
        self.setZValue(-1)  # behind nodes

        # register with nodes
        for node in [start_node, end_node]:
            if not hasattr(node, 'arrows'):
                node.arrows = []
            node.arrows.append(self)

        self.update_position()

        # Add to scene if provided
        if scene:
            scene.addItem(self)

    def update_position(self):
        start_pos = self.start_node.scenePos()
        end_pos = self.end_node.scenePos()
        
        # Calculate direction vector
        dx = end_pos.x() - start_pos.x()
        dy = end_pos.y() - start_pos.y()
        length = math.sqrt(dx*dx + dy*dy)
        
        if length == 0:
            return
        
        # Normalize direction
        dx /= length
        dy /= length
        
        # Get node radii
        start_radius = self.start_node.get_radius()
        end_radius = self.end_node.get_radius()
        
        # Calculate start and end points at edge of nodes
        start_x = start_pos.x() + dx * start_radius
        start_y = start_pos.y() + dy * start_radius
        end_x = end_pos.x() - dx * end_radius
        end_y = end_pos.y() - dy * end_radius
        
        # Create path with line and two arrowheads
        path = QPainterPath()
        path.moveTo(start_x, start_y)
        path.lineTo(end_x, end_y)
        
        # Add arrowhead at end
        self._add_arrowhead(path, end_x, end_y, dx, dy, reverse=False)
        
        # Add arrowhead at start (pointing opposite direction)
        self._add_arrowhead(path, start_x, start_y, -dx, -dy, reverse=False)
        
        self.setPath(path)
    
    def _add_arrowhead(self, path, x, y, dx, dy, reverse=False):
        """Add an arrowhead at position (x, y) pointing in direction (dx, dy)"""
        # Calculate perpendicular vector
        perp_x = -dy
        perp_y = dx
        
        # Offset the tip slightly inward so it's centered on the line endpoint
        tip_offset = 2
        tip_x = x - dx * tip_offset
        tip_y = y - dy * tip_offset
        
        # Base of arrow is further back
        base_x = tip_x - dx * self.arrow_size
        base_y = tip_y - dy * self.arrow_size
        
        # Create arrow triangle with centered tip
        arrow = QPolygonF([
            QPointF(tip_x, tip_y),
            QPointF(base_x + perp_x * self.arrow_size/2, 
                   base_y + perp_y * self.arrow_size/2),
            QPointF(base_x - perp_x * self.arrow_size/2, 
                   base_y - perp_y * self.arrow_size/2)
        ])
        
        path.addPolygon(arrow)


class DynamicNetworkEditor(QGraphicsView):
    def __init__(self, hosts=None, guards=None, relays=None, exits=None, servers=None, bg_image=None):
        super().__init__()
        self.scene = QGraphicsScene()
        self.setScene(self.scene)
        self.setRenderHints(QPainter.RenderHint.Antialiasing)
        self.nodes = {}

        # Load background image if provided
        if bg_image:
            pixmap = QPixmap(bg_image)
            self.scene.addPixmap(pixmap)

        # Default nodes
        self.hosts = hosts if hosts is not None else [{'id': f'H{i+1}'} for i in range(2)]
        self.guards = guards if guards is not None else [{'id': f'G{i+1}'} for i in range(10)]
        self.relays = relays if relays is not None else [{'id': f'R{i+1}'} for i in range(10)]
        self.exits = exits if exits is not None else [{'id': f'E{i+1}'} for i in range(10)]
        self.servers = servers if servers is not None else [{'id': f'S{i+1}'} for i in range(2)]

        self.positions = {}
        self._compute_positions()
        self._draw_nodes()

    def highlight_nodes(self, node_ids, color="#e74c3c", thickness=4):
        """Highlight the given nodes with a colored border"""
        for node_id in node_ids:
            node = self.nodes.get(node_id)
            if node:
                pen = QPen(QColor(color), thickness)
                node.setPen(pen)

    def _compute_positions(self):
        # spacing between nodes
        self.node_spacing = 80
        self.margin = 50

        def vertical_positions(num):
            # start at margin, go down
            return [self.margin + i * self.node_spacing for i in range(num)]
        
        def centered_vertical_positions(num, total_height):
            """Center nodes vertically in the available space"""
            required_height = (num - 1) * self.node_spacing
            start_y = (total_height - required_height) / 2
            return [start_y + i * self.node_spacing for i in range(num)]

        # Calculate total height based on the longest column
        max_nodes = max(len(self.guards), len(self.relays), len(self.exits))
        total_height = self.margin * 2 + max_nodes * self.node_spacing

        self.host_y_positions = centered_vertical_positions(len(self.hosts), total_height)
        self.guard_y_positions = vertical_positions(len(self.guards))
        self.relay_y_positions = vertical_positions(len(self.relays))
        self.exit_y_positions = vertical_positions(len(self.exits))
        self.server_y_positions = centered_vertical_positions(len(self.servers), total_height)

        # X positions
        self.x_positions = {'host': 0, 'guard': 300, 'relay': 600, 'exit': 900, 'server': 1200}

    def _draw_nodes(self):
        radius = 30
        square_size = 50
        server_size = (70, 50)

        # Draw nodes
        for i, node in enumerate(self.hosts):
            x, y = self.x_positions['host'], self.host_y_positions[i]
            n = DraggableNode(x, y, radius, '#3498db', node['id'], 'host')
            self.scene.addItem(n)
            self.nodes[node['id']] = n

        for i, node in enumerate(self.guards):
            x, y = self.x_positions['guard'], self.guard_y_positions[i]
            n = RectNode(x, y, square_size, square_size, '#9b59b6', node['id'], 'square')
            self.scene.addItem(n)
            self.nodes[node['id']] = n

        for i, node in enumerate(self.relays):
            x, y = self.x_positions['relay'], self.relay_y_positions[i]
            n = RectNode(x, y, square_size, square_size, '#2ecc71', node['id'], 'square')
            self.scene.addItem(n)
            self.nodes[node['id']] = n

        for i, node in enumerate(self.exits):
            x, y = self.x_positions['exit'], self.exit_y_positions[i]
            n = RectNode(x, y, square_size, square_size, '#f39c12', node['id'], 'square')
            self.scene.addItem(n)
            self.nodes[node['id']] = n

        for i, node in enumerate(self.servers):
            x, y = self.x_positions['server'], self.server_y_positions[i]
            w, h = server_size
            n = RectNode(x, y, w, h, '#e74c3c', node['id'], 'server')
            self.scene.addItem(n)
            self.nodes[node['id']] = n

        # Expand scene rect
        min_x = min(self.x_positions.values()) - 200
        max_x = max(self.x_positions.values()) + 200
        min_y = self.margin - 100
        max_y = max(max(self.host_y_positions + self.guard_y_positions +
                        self.relay_y_positions + self.exit_y_positions +
                        self.server_y_positions) + 100, 600)
        self.scene.setSceneRect(min_x, min_y, max_x - min_x, max_y - min_y)

        # Center view on the middle
        self.centerOn((min_x + max_x) / 2, (min_y + max_y) / 2)

    def set_node_clickable(self, node_id, callback):
        """Make a specific node clickable with a callback"""
        if node_id in self.nodes:
            self.nodes[node_id].set_click_callback(callback)

    def draw_connection_path(self, node_ids, color):
        print(f"Drawing connection path: {node_ids}")

        if len(node_ids) < 2:
            print("Not enough nodes to draw a connection")
            return

        for start_id, end_id in zip(node_ids, node_ids[1:]):
            start_node = self.nodes.get(start_id)
            end_node = self.nodes.get(end_id)
            if start_node is None or end_node is None:
                print(f"Missing node: {start_id} or {end_id}")
                continue
            BidirectionalArrow(start_node, end_node, color, scene=self.scene)

        # Expand scene to fit all items
        self.scene.setSceneRect(self.scene.itemsBoundingRect().adjusted(-50, -50, 50, 50))

    def remove_connection_path(self, node_ids):
        """Remove arrows connecting the given node_ids"""
        if len(node_ids) < 2:
            return

        arrows_to_remove = []
        for item in self.scene.items():
            if isinstance(item, BidirectionalArrow):
                start_id = getattr(item.start_node, 'node_id', None)
                end_id = getattr(item.end_node, 'node_id', None)
                # check if arrow matches the path
                for sid, eid in zip(node_ids, node_ids[1:]):
                    if (start_id == sid and end_id == eid) or (start_id == eid and end_id == sid):
                        arrows_to_remove.append(item)
                        break

        for arrow in arrows_to_remove:
            # Remove from nodes' arrow lists
            if hasattr(arrow.start_node, 'arrows'):
                arrow.start_node.arrows.remove(arrow)
            if hasattr(arrow.end_node, 'arrows'):
                arrow.end_node.arrows.remove(arrow)
            self.scene.removeItem(arrow)