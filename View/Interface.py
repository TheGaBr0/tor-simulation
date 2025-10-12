from PyQt6.QtWidgets import (QGraphicsView, QGraphicsScene, QGraphicsEllipseItem, 
                             QGraphicsRectItem, QGraphicsTextItem, QGraphicsItem, 
                             QGraphicsPathItem)
from PyQt6.QtGui import QPen, QBrush, QColor, QPixmap, QPainter, QPainterPath, QPolygonF
from PyQt6.QtCore import Qt, QPointF
from collections import defaultdict
import math


class DraggableNode(QGraphicsEllipseItem):
    """
    Circular node that can be clicked (left) and dragged (right-click).
    Used for host nodes in the network visualization.
    """
    
    def __init__(self, x, y, radius, color, node_id, node_type):
        super().__init__(-radius, -radius, 2*radius, 2*radius)
        self.setBrush(QBrush(QColor(color)))
        self.setPen(QPen(Qt.GlobalColor.black, 2))
        self.setPos(x, y)

        self.setFlags(QGraphicsItem.GraphicsItemFlag.ItemSendsScenePositionChanges)

        self.node_id = node_id
        self.node_type = node_type
        self.radius = radius
        self.click_callback = None
        self._dragging = False

        # Add text label in the center
        self.text = QGraphicsTextItem(str(node_id))
        self.text.setDefaultTextColor(Qt.GlobalColor.white)
        self.text.setParentItem(self)
        self.text.setPos(-radius/2, -radius/2)

    def mousePressEvent(self, event):
        """Handle mouse press - left click triggers callback, right click starts drag."""
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
        """Handle dragging with right mouse button."""
        if self._dragging:
            new_pos = event.scenePos() - self._drag_start_pos
            self.setPos(new_pos)
            event.accept()
        else:
            super().mouseMoveEvent(event)

    def mouseReleaseEvent(self, event):
        """Stop dragging on right button release."""
        if event.button() == Qt.MouseButton.RightButton:
            self._dragging = False
            event.accept()
        else:
            super().mouseReleaseEvent(event)

    def get_radius(self):
        """Return the radius for arrow endpoint calculations."""
        return self.radius

    def set_click_callback(self, callback):
        """Set callback function for left-click events."""
        self.click_callback = callback

    def itemChange(self, change, value):
        """Update connected arrows when node position changes."""
        if change == QGraphicsItem.GraphicsItemChange.ItemPositionHasChanged:
            for arrow in getattr(self, 'arrows', []):
                arrow.update_position()
        return super().itemChange(change, value)


class RectNode(QGraphicsRectItem):
    """
    Rectangular node that can be clicked and dragged.
    Used for guard, relay, exit, and server nodes.
    """
    
    def __init__(self, x, y, width, height, color, node_id, node_type):
        super().__init__(-width/2, -height/2, width, height)
        self.setBrush(QBrush(QColor(color)))
        self.setPen(QPen(Qt.GlobalColor.black, 2))
        self.setPos(x, y)

        self.setFlags(QGraphicsItem.GraphicsItemFlag.ItemSendsScenePositionChanges)

        self.node_id = node_id
        self.node_type = node_type
        self.width = width
        self.height = height
        self.click_callback = None
        self._dragging = False

        # Add text label
        self.text = QGraphicsTextItem(str(node_id))
        self.text.setDefaultTextColor(Qt.GlobalColor.white)
        self.text.setParentItem(self)
        self.text.setPos(-width/4, -height/4)

    def mousePressEvent(self, event):
        """Handle mouse press - left click triggers callback, right click starts drag."""
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
        """Handle dragging with right mouse button."""
        if self._dragging:
            new_pos = event.scenePos() - self._drag_start_pos
            self.setPos(new_pos)
            event.accept()
        else:
            super().mouseMoveEvent(event)

    def mouseReleaseEvent(self, event):
        """Stop dragging on right button release."""
        if event.button() == Qt.MouseButton.RightButton:
            self._dragging = False
            event.accept()
        else:
            super().mouseReleaseEvent(event)

    def get_radius(self):
        """Return diagonal half-length for arrow endpoint calculations."""
        return math.sqrt((self.width/2)**2 + (self.height/2)**2)

    def set_click_callback(self, callback):
        """Set callback function for left-click events."""
        self.click_callback = callback

    def itemChange(self, change, value):
        """Update connected arrows when node position changes."""
        if change == QGraphicsItem.GraphicsItemChange.ItemPositionHasChanged:
            for arrow in getattr(self, 'arrows', []):
                arrow.update_position()
        return super().itemChange(change, value)


class BidirectionalArrow(QGraphicsPathItem):
    """
    Bidirectional arrow connecting two nodes with arrowheads on both ends.
    Supports parallel arrows with automatic offset calculation.
    """
    
    def __init__(self, start_node, end_node, color, offset=0, scene=None):
        super().__init__()
        self.start_node = start_node
        self.end_node = end_node
        self.arrow_size = 12
        self.offset = offset  # Perpendicular offset for multiple parallel arrows

        pen = QPen(QColor(color), 3)
        pen.setCapStyle(Qt.PenCapStyle.RoundCap)
        pen.setJoinStyle(Qt.PenJoinStyle.RoundJoin)
        self.setPen(pen)
        self.setBrush(QBrush(QColor(color)))
        self.setZValue(-1)  # Draw arrows behind nodes

        # Register this arrow with both nodes
        for node in [start_node, end_node]:
            if not hasattr(node, 'arrows'):
                node.arrows = []
            node.arrows.append(self)

        self.update_position()

        if scene:
            scene.addItem(self)

    def update_position(self):
        """Recalculate arrow path when nodes move."""
        start_pos = self.start_node.scenePos()
        end_pos = self.end_node.scenePos()

        dx = end_pos.x() - start_pos.x()
        dy = end_pos.y() - start_pos.y()
        length = math.sqrt(dx*dx + dy*dy)

        if length == 0:
            return

        # Normalize direction vector
        dx /= length
        dy /= length

        # Calculate perpendicular vector for offset
        perp_x = -dy
        perp_y = dx

        start_radius = self.start_node.get_radius()
        end_radius = self.end_node.get_radius()

        # Apply perpendicular offset to both endpoints
        offset_x = perp_x * self.offset
        offset_y = perp_y * self.offset

        # Calculate start and end points accounting for node radius
        start_x = start_pos.x() + dx * start_radius + offset_x
        start_y = start_pos.y() + dy * start_radius + offset_y
        end_x = end_pos.x() - dx * end_radius + offset_x
        end_y = end_pos.y() - dy * end_radius + offset_y

        # Draw line
        path = QPainterPath()
        path.moveTo(start_x, start_y)
        path.lineTo(end_x, end_y)

        # Add arrowheads at both ends
        self._add_arrowhead(path, end_x, end_y, dx, dy)
        self._add_arrowhead(path, start_x, start_y, -dx, -dy)

        self.setPath(path)

    def _add_arrowhead(self, path, x, y, dx, dy):
        """Add a triangular arrowhead at the specified position."""
        # Calculate perpendicular direction for arrow width
        perp_x = -dy
        perp_y = dx

        # Offset tip slightly inward
        tip_offset = 2
        tip_x = x - dx * tip_offset
        tip_y = y - dy * tip_offset

        # Calculate base of arrowhead
        base_x = tip_x - dx * self.arrow_size
        base_y = tip_y - dy * self.arrow_size

        # Create triangle
        arrow = QPolygonF([
            QPointF(tip_x, tip_y),
            QPointF(base_x + perp_x * self.arrow_size/2,
                    base_y + perp_y * self.arrow_size/2),
            QPointF(base_x - perp_x * self.arrow_size/2,
                    base_y - perp_y * self.arrow_size/2)
        ])
        path.addPolygon(arrow)


class DynamicNetworkEditor(QGraphicsView):
    """
    Main network visualization widget.
    Manages node layout, circuit rendering, and interactive features.
    """
    
    def __init__(self, circuits=None, hosts=None, guards=None, relays=None, 
                 exits=None, servers=None, bg_image=None):
        super().__init__()
        self.scene = QGraphicsScene()
        self.setScene(self.scene)
        self.setRenderHints(QPainter.RenderHint.Antialiasing)
        
        self.nodes = {}
        self.circuits = circuits if circuits is not None else defaultdict(list)
        self.circuit_arrows = defaultdict(list)
        
        # Track which circuits use each edge for parallel arrow positioning
        self.edge_to_circuits = defaultdict(list)
        self.arrow_offset_spacing = 8  # Distance between parallel arrows in pixels

        # Optional background image
        if bg_image:
            pixmap = QPixmap(bg_image)
            self.scene.addPixmap(pixmap)

        # Initialize node lists with defaults
        self.hosts = hosts if hosts is not None else [{'id': f'H{i+1}'} for i in range(2)]
        self.guards = guards if guards is not None else [{'id': f'G{i+1}'} for i in range(10)]
        self.relays = relays if relays is not None else [{'id': f'R{i+1}'} for i in range(10)]
        self.exits = exits if exits is not None else [{'id': f'E{i+1}'} for i in range(10)]
        self.servers = servers if servers is not None else [{'id': f'S{i+1}'} for i in range(2)]

        self.positions = {}
        self._compute_positions()
        self._draw_nodes()

    def highlight_nodes(self, node_ids, color="#ff0000", thickness=4):
        """Highlight specified nodes by changing their border color and thickness."""
        for node_id in node_ids:
            node = self.nodes.get(node_id)
            if node:
                pen = QPen(QColor(color), thickness)
                node.setPen(pen)

    def _compute_positions(self):
        """Calculate x,y positions for all nodes in a layered layout."""
        self.node_spacing = 80
        self.margin = 50

        def vertical_positions(num):
            """Calculate evenly spaced vertical positions starting from margin."""
            return [self.margin + i * self.node_spacing for i in range(num)]

        def centered_vertical_positions(num, total_height):
            """Calculate centered vertical positions within total_height."""
            required_height = (num - 1) * self.node_spacing
            start_y = (total_height - required_height) / 2
            return [start_y + i * self.node_spacing for i in range(num)]

        # Calculate total height based on largest layer
        max_nodes = max(len(self.guards), len(self.relays), len(self.exits))
        total_height = self.margin * 2 + max_nodes * self.node_spacing

        # Position each layer
        self.host_y_positions = centered_vertical_positions(len(self.hosts), total_height)
        self.guard_y_positions = vertical_positions(len(self.guards))
        self.relay_y_positions = vertical_positions(len(self.relays))
        self.exit_y_positions = vertical_positions(len(self.exits))
        self.server_y_positions = centered_vertical_positions(len(self.servers), total_height)

        # Horizontal positions for each layer
        self.x_positions = {
            'host': 0, 
            'guard': 300, 
            'relay': 600, 
            'exit': 900, 
            'server': 1200
        }

    def _draw_nodes(self):
        """Create and add all node graphics to the scene."""
        radius = 30
        square_size = 50
        server_size = (70, 50)

        # Draw hosts (circular)
        for i, node in enumerate(self.hosts):
            x, y = self.x_positions['host'], self.host_y_positions[i]
            n = DraggableNode(x, y, radius, '#3498db', node['id'], 'host')
            self.scene.addItem(n)
            self.nodes[node['id']] = n

        # Draw guards (square)
        for i, node in enumerate(self.guards):
            x, y = self.x_positions['guard'], self.guard_y_positions[i]
            n = RectNode(x, y, square_size, square_size, '#9b59b6', node['id'], 'guard')
            self.scene.addItem(n)
            self.nodes[node['id']] = n

        # Draw relays (square)
        for i, node in enumerate(self.relays):
            x, y = self.x_positions['relay'], self.relay_y_positions[i]
            n = RectNode(x, y, square_size, square_size, '#2ecc71', node['id'], 'relay')
            self.scene.addItem(n)
            self.nodes[node['id']] = n

        # Draw exits (square)
        for i, node in enumerate(self.exits):
            x, y = self.x_positions['exit'], self.exit_y_positions[i]
            n = RectNode(x, y, square_size, square_size, '#f39c12', node['id'], 'exit')
            self.scene.addItem(n)
            self.nodes[node['id']] = n

        # Draw servers (rectangle)
        for i, node in enumerate(self.servers):
            x, y = self.x_positions['server'], self.server_y_positions[i]
            w, h = server_size
            n = RectNode(x, y, w, h, '#e74c3c', node['id'], 'server')
            self.scene.addItem(n)
            self.nodes[node['id']] = n

        # Set scene boundaries with padding
        min_x = min(self.x_positions.values()) - 200
        max_x = max(self.x_positions.values()) + 200
        min_y = self.margin - 100
        max_y = max(max(self.host_y_positions + self.guard_y_positions +
                        self.relay_y_positions + self.exit_y_positions +
                        self.server_y_positions) + 100, 600)
        self.scene.setSceneRect(min_x, min_y, max_x - min_x, max_y - min_y)
        self.centerOn((min_x + max_x) / 2, (min_y + max_y) / 2)

    def set_node_clickable(self, node_id, callback):
        """Register a callback for when a node is clicked."""
        if node_id in self.nodes:
            self.nodes[node_id].set_click_callback(callback)

    def draw_circuit(self, circuit_id, color="#2c3e50"):
        """
        Draw all edges for a circuit with proper offset to avoid overlapping arrows.
        Automatically calculates offsets for parallel circuits.
        """
        node_ids = self.circuits.get(circuit_id, [])
        if len(node_ids) < 2:
            return

        arrows = []
        for start_id, end_id in zip(node_ids, node_ids[1:]):
            start_node = self.nodes.get(start_id)
            end_node = self.nodes.get(end_id)
            if start_node and end_node:
                # Track edge usage
                edge = (start_id, end_id)
                self.edge_to_circuits[edge].append(circuit_id)
                
                # Calculate offset based on number of circuits using this edge
                num_circuits = len(self.edge_to_circuits[edge])
                offset = self._calculate_offset(num_circuits - 1, num_circuits)
                
                arrow = BidirectionalArrow(start_node, end_node, color, 
                                          offset=offset, scene=self.scene)
                arrows.append(arrow)

        self.circuit_arrows[circuit_id] = arrows
        self.scene.setSceneRect(self.scene.itemsBoundingRect().adjusted(-50, -50, 50, 50))

    def _calculate_offset(self, index, total):
        """
        Calculate perpendicular offset for arrow positioning.
        Centers multiple arrows around the base line between nodes.
        """
        if total == 1:
            return 0
        
        # Center arrows symmetrically around 0
        base_offset = -(total - 1) * self.arrow_offset_spacing / 2
        return base_offset + index * self.arrow_offset_spacing

    def remove_circuit(self, circuit_id):
        """
        Remove all edges of a circuit and reposition remaining arrows.
        This ensures clean removal without leaving gaps in parallel arrows.
        """
        arrows = self.circuit_arrows.get(circuit_id, [])
        
        # Track which edges need arrow repositioning
        edges_to_update = set()
        
        for arrow in arrows:
            start_id = arrow.start_node.node_id
            end_id = arrow.end_node.node_id
            edge = (start_id, end_id)
            
            # Remove circuit from edge tracking
            if edge in self.edge_to_circuits and circuit_id in self.edge_to_circuits[edge]:
                self.edge_to_circuits[edge].remove(circuit_id)
                edges_to_update.add(edge)
                
                # Clean up empty entries
                if not self.edge_to_circuits[edge]:
                    del self.edge_to_circuits[edge]
            
            # Unregister arrow from nodes
            if hasattr(arrow.start_node, 'arrows'):
                if arrow in arrow.start_node.arrows:
                    arrow.start_node.arrows.remove(arrow)
            if hasattr(arrow.end_node, 'arrows'):
                if arrow in arrow.end_node.arrows:
                    arrow.end_node.arrows.remove(arrow)
            
            # Remove from scene
            self.scene.removeItem(arrow)
        
        # Clean up circuit arrows entry
        if circuit_id in self.circuit_arrows:
            del self.circuit_arrows[circuit_id]
        
        # Reposition remaining arrows to close gaps
        self._reposition_arrows_on_edges(edges_to_update)

    def _reposition_arrows_on_edges(self, edges):
        """
        Recalculate offsets for all arrows on the given edges.
        Called after circuit removal to maintain proper spacing.
        """
        for edge in edges:
            if edge not in self.edge_to_circuits:
                continue
            
            circuits = self.edge_to_circuits[edge]
            total = len(circuits)
            
            # Update offset for each circuit's arrow on this edge
            for i, cid in enumerate(circuits):
                arrows = self.circuit_arrows.get(cid, [])
                for arrow in arrows:
                    if (arrow.start_node.node_id, arrow.end_node.node_id) == edge:
                        arrow.offset = self._calculate_offset(i, total)
                        arrow.update_position()

    def remove_edge_arrows(self, start_id, end_id):
        """
        Remove all circuits that use a specific edge.
        Useful for simulating link failures or attacks.
        """
        # Find all circuits using this edge
        circuits_to_remove = []
        for circuit_id, arrows in list(self.circuit_arrows.items()):
            for arrow in list(arrows):
                if (arrow.start_node.node_id == start_id and 
                    arrow.end_node.node_id == end_id):
                    circuits_to_remove.append(circuit_id)
                    break
        
        # Remove each circuit (handles cleanup properly)
        for circuit_id in circuits_to_remove:
            self.remove_circuit(circuit_id)