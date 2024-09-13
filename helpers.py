from flask import jsonify


def get_listings_by_customer_id(customer_id, Listing):
    listings = Listing.query.filter_by(customer_id=customer_id).all()
    return_listings = []
    for listing in listings:
        return_listings.append({
            "id": listing.id,
            "title": listing.title,
            "description": listing.description,
            "price": listing.price,
            "zipcode": listing.zipcode,
            "image": listing.image
        })
    return return_listings
