from rest_framework import serializers

from backend.models import Contact, User, Category, Shop, Product, ProductParameter, ProductInfo, OrderItem, Order, ConfirmEmailToken

class ConfirmEmailTokenSerializer(serializers.ModelSerializer):
    class Meta:
        model = ConfirmEmailToken
        fields = ['key']

class ContactSerializer(serializers.ModelSerializer):

    class Meta:
        model = Contact
        fields = ('id', 'country', 'region', 'city', 'street', 'house', 'structure', 'building', 'apartment', 'user',
                'phone', 'postal_code')
        read_only_fields = ('id',)
        extra_kwargs = {
            'user': {'write_only': True}
        }

class UserSerializer(serializers.ModelSerializer):
    contacts = ContactSerializer(read_only=True, many=True)

    class Meta:
        model = User
        fields = ('id', 'first_name', 'last_name', 'email', 'company', 'position', 'contacts', 'type')
        read_only_fields = ('id', )

class CategorySerializer(serializers.ModelSerializer):

    class Meta:
        model = Category
        fields = ('id', 'name')
        read_only_fields = ('id', )

class ShopSerializer(serializers.ModelSerializer):
    
    class Meta:
        model = Shop
        fields = ('id', 'name', 'state', 'user', 'url')


class ProductSerializer(serializers.ModelSerializer):
    category = serializers.StringRelatedField()

    class Meta:
        model = Product
        fields = ('name', 'category',)

class ProductParameterSerializer(serializers.ModelSerializer):
    parameter = serializers.StringRelatedField()

    class Meta:
        model = ProductParameter
        fields = ('parameter', 'value',)

class ProductInfoSerializer(serializers.ModelSerializer):
    product = ProductSerializer(read_only=True)
    product_parameters = ProductParameterSerializer(read_only=True, many=True)
    image = serializers.ImageField(required=False) 

    class Meta:
        model = ProductInfo
        fields = ('id', 'model', 'product', 'shop', 'quantity', 'price', 'price_rrc', 'product_parameters', 'image',)
        read_only_fields = ('id',)

    def create(self, validated_data):
        image = validated_data.pop('image', None)
        product_info = ProductInfo.objects.create(**validated_data)
        if image:
            product_info.image = image
            product_info.save()
        return product_info

class OrderItemSerializer(serializers.ModelSerializer):

    class Meta:
        model = OrderItem
        fields = ('id', 'product_info', 'quantity', 'order', 'shop',)
        read_only_fields = ('id', )
        extra_kwargs = {
            'order': {'write_only': True}
        }

class OrderItemCreateSerializer(OrderItemSerializer):
    product_info = ProductInfoSerializer(read_only=True)

class OrderSerializer(serializers.ModelSerializer):
    ordered_items = OrderItemCreateSerializer(read_only=True, many=True)

    total_sum = serializers.IntegerField()
    contact = ContactSerializer(read_only=True)

    class Meta:
        model = Order
        fields = ('id', 'ordered_items', 'state', 'total_sum', 'contact',)
        read_only_fields = ('id', )